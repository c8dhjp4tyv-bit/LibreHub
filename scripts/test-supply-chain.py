#!/usr/bin/env python3
"""Real M3 Git -> M1 Flatpak -> Ed25519/OpenSSL -> M2 signed publication -> install.
Also runs the offline verifier and deterministic/nondeterministic rebuilds.
"""
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import sqlite3
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from source_fixture import SourceFixture, REPOSITORY, git
ROOT=Path(__file__).resolve().parents[1]
API='http://127.0.0.1:8080'
APP='org.librehub.ProjectHello'
spec=importlib.util.spec_from_file_location('independent_validation',ROOT/'scripts/validate-attestation.py')
validation=importlib.util.module_from_spec(spec);spec.loader.exec_module(validation)

def run(args,env,**kw):
    return subprocess.check_output([str(a) for a in args],env=env,text=True,timeout=1200,**kw).strip()

def main():
    proof=ROOT/'data/m6-proof';proof.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='librehub-m6-') as temp:
        work=Path(temp);fixture=SourceFixture(work/'git');env=os.environ.copy();env.update(fixture.env());env['LIBREHUB_DATA_DIR']=str(work/'data')
        env['LIBREHUB_ATTESTOR_KEY_FILE']=str(work/'attestor.seed');env['LIBREHUB_ATTESTOR_KEYS_FILE']=str(work/'trusted-keys.json')
        env['LIBREHUB_SUPPLY_CHAIN_POLICY']='audit_only'
        if os.environ.get('LIBREHUB_M6_HARDENED')=='1':
            env['LIBREHUB_DOCKER']='podman';env['LIBREHUB_WORKER_ISOLATION']='hardened';env['LIBREHUB_SUPPLY_CHAIN_POLICY']='enforce'
        runtime=env.get('LIBREHUB_DOCKER','docker');image=env.get('LIBREHUB_WORKER_IMAGE','librehub-worker:m1')
        image_id=run([runtime,'image','inspect','--format={{.Id}}',image],env)
        env['LIBREHUB_ALLOWED_WORKER_IMAGE_IDS']=image_id if image_id.startswith('sha256:') else 'sha256:'+image_id
        admin=ROOT/'target/debug/librehub-admin';verifier=ROOT/'target/debug/librehub-verify'
        keys=json.loads(run([admin,'attestor','provision',env['LIBREHUB_ATTESTOR_KEY_FILE'],env['LIBREHUB_ATTESTOR_KEYS_FILE']],env))
        (proof/'trusted-keys.json').write_text(json.dumps(keys))
        developer=json.loads(run([admin,'create-developer','M6 acceptance'],env));token=json.loads(run([admin,'create-token',developer['id'],'M6 acceptance'],env))['token']
        log=open(proof/'acceptance.log','w');process=None
        def request(path,data=None,raw=False):
            body=None if data is None else json.dumps(data).encode()
            headers={'Content-Type':'application/json','Authorization':'Bearer '+token}
            with urllib.request.urlopen(urllib.request.Request(API+path,data=body,headers=headers),timeout=90) as response:
                content=response.read(2*1024*1024+1)
                assert len(content)<=2*1024*1024
                return content if raw else json.loads(content)
        def wait(path,predicate,timeout=1200):
            deadline=time.monotonic()+timeout
            while time.monotonic()<deadline:
                if process.poll() is not None: raise RuntimeError('API exited; see acceptance.log')
                try:
                    value=request(path)
                    if predicate(value):return value
                    if value.get('status') in ['failed','cancelled'] or value.get('needs_attention'):raise AssertionError(value)
                except (urllib.error.URLError,ConnectionResetError):pass
                time.sleep(.2)
            raise TimeoutError(path)
        def start(stage=None):
            nonlocal process
            start_env=env.copy()
            if stage:start_env['LIBREHUB_TEST_ATTESTATION_FAULT_STAGE']=stage
            process=subprocess.Popen([ROOT/'target/debug/librehub-api'],env=start_env,stdout=log,stderr=log);wait('/ready',lambda v:v['ready'])
        def stop(crash=False):
            if process and process.poll() is None:process.send_signal(signal.SIGKILL if crash else signal.SIGTERM);process.wait(timeout=120)
        try:
            start('build_evidence')
            project=request('/api/v1/projects',{'slug':'m6-hello','display_name':'M6 Hello','repository':{'provider':'git','url':REPOSITORY},'default_branch':'main','auto_build':False,'build_branches':['main'],'build_tags':True})['project']['id']
            def build():
                trigger=request(f'/api/v1/projects/{project}/builds',{'ref':'main'})
                wait(f'/api/v1/projects/{project}/source-events/{trigger["source_event_id"]}',lambda v:v['status']=='completed')
                return wait('/api/v1/builds/'+trigger['build_id'],lambda v:v['status']=='succeeded')
            b=build();assert b['provenance']['revision']['commit']==fixture.commit1
            crashes=[]
            def signing_crash(stage,following=None):
                marker=work/'data'/('attestation-fault-'+stage);deadline=time.monotonic()+180
                while not marker.exists() and time.monotonic()<deadline:
                    assert process.poll() is None
                    time.sleep(.05)
                assert marker.exists(),stage
                stop(crash=True);crashes.append(stage);start(following)
            for stage,following in [('build_evidence','build_verified'),('build_verified','build_signed'),('build_signed','build_persisted'),('build_persisted',None)]:signing_crash(stage,following)
            with sqlite3.connect(work/'data/builds.sqlite3') as db:
                assert db.execute('SELECT count(*) FROM builds WHERE id=?',(b['id'],)).fetchone()[0]==1
                assert db.execute('SELECT count(*) FROM build_attestations WHERE build_id=?',(b['id'],)).fetchone()[0]==1
            artifact=work/'data'/b['result']['artifacts'][0]['path'];assert hashlib.sha256(artifact.read_bytes()).hexdigest()==b['result']['artifacts'][0]['sha256']
            stop();start('release_verified')
            pub=request('/api/v1/builds/'+b['id']+'/publish',{'channel':'stable'});pub=wait('/api/v1/publishes/'+pub['id'],lambda v:v['status']=='succeeded')
            path=f'/api/v1/catalog/apps/{APP}/releases/{pub["id"]}'
            for stage,following in [('release_verified','release_signed'),('release_signed','release_persisted'),('release_persisted',None)]:signing_crash(stage,following)
            evidence=wait(path+'/provenance',lambda v:v['verification']['verified']);bundle=request(path+'/attestation/download');(proof/'attestation.json').write_text(json.dumps(bundle))
            sbom=request(path+'/sbom/download',raw=True);(proof/'sbom.spdx.json').write_bytes(sbom)
            for name in ['build','release']:
                envelope=bundle[name];payload=base64.b64decode(envelope['payload'],validate=True);statement=json.loads(payload);validation.validate_statement(statement)
                key=next(k for k in keys['keys'] if k['key_id']==envelope['signatures'][0]['keyid'])
                (work/'public.der').write_bytes(bytes.fromhex('302a300506032b6570032100')+base64.b64decode(key['public_key']))
                (work/'pae').write_bytes(b'DSSEv1 '+str(len(envelope['payloadType'].encode())).encode()+b' '+envelope['payloadType'].encode()+b' '+str(len(payload)).encode()+b' '+payload)
                (work/'sig').write_bytes(base64.b64decode(envelope['signatures'][0]['sig']))
                run(['openssl','pkeyutl','-verify','-pubin','-inkey',work/'public.der','-keyform','DER','-rawin','-in',work/'pae','-sigfile',work/'sig'],env)
                (proof/(name+'-provenance.json')).write_bytes(payload)
            validation.validate_sbom(json.loads(sbom))
            commit=pub['result']['published_ref']['commit'];ref=pub['result']['published_ref']['ref_name']
            verify_args=[verifier,proof/'attestation.json',proof/'trusted-keys.json','--ref',ref,'--checksum',commit,'--publication-id',pub['id'],'--artifact',artifact,'--sbom',proof/'sbom.spdx.json']
            assert json.loads(run(verify_args,env))['verified']
            tampering=[]
            original=json.dumps(bundle)
            for name in ['payload','signature','artifact','checksum','key','subject','sbom','commit','snapshot','manifest','publication','revoked_key']:
                altered=json.loads(original);args=verify_args.copy()
                if name=='payload':
                    statement=json.loads(base64.b64decode(altered['release']['payload']));statement['predicate']['publicationId']='22222222-2222-4222-8222-222222222222';altered['release']['payload']=base64.b64encode(json.dumps(statement).encode()).decode()
                elif name=='signature':altered['build']['signatures'][0]['sig']=base64.b64encode(bytes(64)).decode()
                elif name=='artifact':
                    bad=work/'bad.flatpak';bad.write_bytes(b'altered bundle');args[args.index('--artifact')+1]=bad
                elif name=='checksum':args[args.index('--checksum')+1]='0'*64
                elif name=='subject':args[args.index('--ref')+1]='app/org.wrong.App/x86_64/master'
                elif name=='sbom':
                    bad=work/'changed-sbom.json';bad.write_text('{}');args[args.index('--sbom')+1]=bad
                elif name in ['commit','snapshot','manifest']:
                    args.extend(['--'+name,'0'*(40 if name=='commit' else 64)])
                elif name=='publication':args[args.index('--publication-id')+1]='22222222-2222-4222-8222-222222222222'
                elif name=='revoked_key':
                    revoked=json.loads(json.dumps(keys));revoked['keys'][0]['state']='revoked';other=work/'revoked.json';other.write_text(json.dumps(revoked));args[2]=other
                else:
                    other=work/'other-keys.json';run([admin,'attestor','provision',work/'other-seed',other],env);args[2]=other
                altered_file=work/'altered.json';altered_file.write_text(json.dumps(altered));args[1]=altered_file
                result=subprocess.run([str(a) for a in args],env=env,text=True,capture_output=True,timeout=30);assert result.returncode!=0;assert json.loads(result.stdout)['code']=='verification_failed';tampering.append(name)
            # Normal client trust remains GPG-enabled, and installed commit matches release subject.
            client=env.copy()
            for name in list(client):
                if name.startswith(('LIBREHUB_','REPO_')):client.pop(name)
            for name,part in [('HOME','client'),('XDG_DATA_HOME','client/data'),('XDG_CONFIG_HOME','client/config'),('XDG_CACHE_HOME','client/cache'),('XDG_RUNTIME_DIR','client/run')]:
                client[name]=str(work/part);Path(client[name]).mkdir(parents=True,exist_ok=True)
            os.chmod(client['XDG_RUNTIME_DIR'],0o700)
            descriptor=os.environ.get('LIBREHUB_RUNTIME_REPO_URL','https://dl.flathub.org/repo/flathub.flatpakrepo')
            run(['flatpak','remote-add','--user','--if-not-exists','flathub',descriptor],client)
            public=os.environ.get('LIBREHUB_PUBLIC_BASE_URL','http://localhost:8090').rstrip('/')
            run(['flatpak','remote-add','--user','m6-librehub',public+'/librehub.flatpakrepo'],client)
            run(['flatpak','install','--user','--noninteractive','--no-related','m6-librehub',APP],client)
            assert run(['flatpak','info','--user','--show-commit',APP],client)==commit
            output=run(['flatpak','run','--user',APP],client);assert 'Hello from LibreHub project revision 1!' in output
            # Crash after publication, then reconcile the same immutable evidence identity.
            stop(crash=True);start();again=request(path+'/attestation/download');assert again==bundle
            stop()
            deterministic=json.loads(run([admin,'builds','verify-reproducibility',b['id']],env))
            for role,build_id in [('original',b['id']),('rebuild',deterministic.get('rebuild_id'))]:
                if build_id:
                    content=work/'data/builds'/build_id/'content-listing.txt'
                    if content.exists():(proof/(role+'-content.txt')).write_bytes(content.read_bytes())
            (proof/'reproducibility.json').write_text(json.dumps(deterministic))
            assert deterministic['state']=='reproduced',deterministic
            # Deliberately varying file contents must remain a visible mismatch.
            manifest_path=fixture.repo/'org.librehub.ProjectHello.json';manifest=json.loads(manifest_path.read_text());manifest['modules'][0]['build-commands'].append('date +%s%N > /app/non-deterministic');manifest_path.write_text(json.dumps(manifest));git(fixture.repo,'add','.');git(fixture.repo,'commit','-m','Deliberately nondeterministic fixture')
            start();nondeterministic_build=build();stop();nondeterministic=json.loads(run([admin,'builds','verify-reproducibility',nondeterministic_build['id']],env));assert nondeterministic['state']=='non_reproducible',nondeterministic
            report={'source_commit':b['provenance']['revision']['commit'],'source_snapshot':b['provenance']['snapshot']['sha256'],'build_id':b['id'],'artifact_sha256':b['result']['artifacts'][0]['sha256'],'publication_id':pub['id'],'published_checksum':commit,'ref':ref,'environment':b['result']['environment'],'attestor_key_id':keys['keys'][0]['key_id'],'independent_openssl':'passed','offline_verifier':'passed','tampering_rejected':tampering,'deterministic':deterministic,'nondeterministic':nondeterministic,'installed_output':output,'restart_evidence_identical':True,'signing_crash_stages':crashes,'commit_sha':run(['git','rev-parse','HEAD'],os.environ.copy())}
            (proof/'proof.json').write_text(json.dumps(report,indent=2));print(json.dumps(report))
        except Exception:
            import difflib
            if (proof/'original-content.txt').exists() and (proof/'rebuild-content.txt').exists():
                print(''.join(difflib.unified_diff((proof/'original-content.txt').read_text().splitlines(True),(proof/'rebuild-content.txt').read_text().splitlines(True),fromfile='original',tofile='rebuild')))
            raise
        finally:
            stop();fixture.close();log.close()
if __name__=='__main__':main()
