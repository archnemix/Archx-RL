"""Validate the synthetic model, accounting, reproducibility and backend examples."""
import json
import random
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT/'tools'), str(ROOT/'demo')]
from synthetic_stability_evaluation import SCENARIOS, evaluate, sample, wilson
from engine import Engine, policy
from sqlite_engine import SQLiteEngine


class StabilityEvaluationTests(unittest.TestCase):
    def test_model_is_reproducible_and_covers_all_scenarios(self):
        result=evaluate(200,4301)
        self.assertEqual(result,evaluate(200,4301))
        self.assertEqual([row['scenario'] for row in result['scenarios']],list(SCENARIOS))
        rows={r['scenario']:r for r in result['scenarios']}
        self.assertEqual(rows['cloned_vm']['outcomes']['different_related'],200)
        self.assertEqual(rows['forged_replay']['outcomes']['different_related'],200)
        self.assertEqual(rows['full_rotation']['outcomes']['same_below'],200)
        self.assertEqual(rows['permissions']['outcomes']['denied_invalid'],60)
        self.assertEqual(rows['shared_nat']['outcomes']['different_related'],25)
        self.assertEqual(rows['reinstall']['outcomes']['same_below'],15)
        self.assertEqual(rows['hardware_change']['outcomes']['same_below'],55)
        for row in rows.values():
            c=row['outcomes']
            self.assertEqual(sum(value for key,value in c.items() if key in ('related','below_threshold','inconclusive','new') or key.startswith('denied_')),200)
            lo,hi=row['conditional_wilson_95']
            self.assertLessEqual(lo,row['conditional_model_event_count']/200)
            self.assertGreaterEqual(hi,row['conditional_model_event_count']/200)
        self.assertNotIn('192.0.2.1',json.dumps(result))
        self.assertIn('Not a representative sample',json.dumps(result))

    def test_selected_cases_agree_across_python_backends(self):
        settings=policy('standard',{'max_requests':10}); rng=random.Random(4301)
        with tempfile.TemporaryDirectory() as tmp:
            for i,scenario in enumerate(SCENARIOS):
                first,second,ip1,ip2,_=sample(scenario,rng,i)
                memory=Engine(settings,secret=b'synthetic-stability-secret',clock=lambda:1000)
                disk=SQLiteEngine(Path(tmp)/f'{i}.sqlite',settings,b'synthetic-stability-secret-32-bytes!',clock=lambda:1000)
                for signals,ip in ((first,ip1),(second,ip2)):
                    left=memory.check({'signals':signals},ip); right=disk.check({'signals':signals},ip)
                    self.assertEqual((left['decision'],left['relation']),(right['decision'],right['relation']))

    def test_statistics_and_invalid_arguments(self):
        self.assertIsNone(wilson(0,0))
        self.assertEqual(wilson(0,200),[0.0,0.0188])
        self.assertEqual(wilson(200,200),[0.9812,1.0])
        for value in (0,-1,10001,True,2.5):
            with self.assertRaises(ValueError): evaluate(value)
        with self.assertRaises(ValueError): sample('unknown',random.Random(1),1)


if __name__=='__main__': unittest.main(verbosity=2)
