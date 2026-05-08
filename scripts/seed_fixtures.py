#!/usr/bin/env python3
"""Seed fixture data into the database for development."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from api.storage import init_db, save_session
from core.analysis.engine import AnalysisEngine
from core.normalizer import normalize
from parsers.paloalto.parser import PaloAltoParser


def main():
    init_db()
    parser = PaloAltoParser()
    engine = AnalysisEngine()

    fixtures = [
        'parsers/paloalto/tests/fixtures/config-minimal.xml',
        'parsers/paloalto/tests/fixtures/config-medium.xml',
        'parsers/paloalto/tests/fixtures/config-complex.xml',
    ]

    for fixture_path in fixtures:
        full_path = os.path.join(os.path.dirname(__file__), '..', fixture_path)
        if not os.path.exists(full_path):
            print(f"Skipping missing fixture: {full_path}")
            continue

        raw_content = open(full_path, 'rb').read()
        ast = parser.parse(raw_content)
        session_data = parser.normalize(ast)

        session = normalize('paloalto', session_data, source_filename=fixture_path, source_content=raw_content)
        result = engine.analyze(session)

        session_dict = session.model_dump()
        session_dict['health_score'] = result.health_score
        session_dict['finding_counts'] = result.finding_counts

        findings = [f.model_dump() for f in result.findings]

        session_id = save_session(session_dict, findings, raw_content, fixture_path)
        print(f"Loaded {fixture_path} → session {session_id[:8]}... ({session.rule_count} rules, health: {result.health_score})")

    print("Done.")


if __name__ == '__main__':
    main()
