#!/usr/bin/env python3
"""Independent upstream in-toto/SLSA protobuf parsing, SPDX schema and references.
No LibreHub Rust types are imported. Crypto acceptance also uses OpenSSL.
"""
import base64
import json
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent / 'schemas'))
from google.protobuf.json_format import ParseDict
from in_toto_attestation.v1.statement_pb2 import Statement
from in_toto_attestation.predicates.provenance.v1.provenance_pb2 import Provenance
from jsonschema import Draft7Validator, FormatChecker

def validate_statement(statement):
    ParseDict(statement, Statement())
    assert statement['_type'] == 'https://in-toto.io/Statement/v1'
    assert statement['subject'] and all(s['digest'] for s in statement['subject'])
    if statement['predicateType'] == 'https://slsa.dev/provenance/v1':
        p = statement['predicate']
        ParseDict(p, Provenance())
        assert p['buildDefinition']['buildType'] and p['runDetails']['builder']['id']
    else:
        assert statement['predicateType'] == 'https://librehub.org/attestations/release/v1'

def validate_sbom(document):
    schema=json.loads((Path(__file__).parent/'schemas/spdx-2.3.schema.json').read_text())
    Draft7Validator(schema, format_checker=FormatChecker()).validate(document)
    ids={document['SPDXID']}
    for p in document['packages']:
        assert p['SPDXID'] not in ids
        ids.add(p['SPDXID'])
        assert p['downloadLocation'] in ['NOASSERTION','NONE'] or '://' in p['downloadLocation']
        for checksum in p.get('checksums',[]):
            if checksum['algorithm']=='SHA256':
                assert len(checksum['checksumValue']) == 64
                assert all(c in '0123456789abcdef' for c in checksum['checksumValue'])
    for r in document.get('relationships',[]):
        assert r['spdxElementId'] in ids and r['relatedSpdxElement'] in ids
    assert document['spdxVersion']=='SPDX-2.3' and document['dataLicense']=='CC0-1.0'

if __name__=='__main__':
    value=json.loads(Path(sys.argv[1]).read_text())
    if 'build' in value and 'release' in value:
        for name in ['build','release']:
            validate_statement(json.loads(base64.b64decode(value[name]['payload'],validate=True)))
    else:
        validate_statement(value)
    if len(sys.argv)>2:
        validate_sbom(json.loads(Path(sys.argv[2]).read_text()))
    print(json.dumps({'schema_validation':'passed'}))
