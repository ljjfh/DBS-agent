"""Regression checks for corrections, dependent tasks and signed internal transfers."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import unittest
from unittest.mock import patch
from qa.run_extended import World, Phase, KernelError
from app.bank.mock_bank import MockBank


class SemanticSafety(unittest.TestCase):
    def setUp(self):
        self.w = World()

    def test_correction_invalidates_old_authorization(self):
        w = self.w
        old = w.prepare('Send 200 to my daughter')
        token = w.authorize()
        w.say('Actually make that 100')
        self.assertEqual(w.s.current_draft.amount_cents, 10000)
        self.assertNotEqual(w.s.current_draft_id, old.draft_id)
        with self.assertRaises(KernelError):
            w.kernel.commit(w.s, old.draft_id, token)
        self.assertEqual(w.balance(), 325000)
        self.assertEqual(w.pay()['amount_cents'], 10000)

    def test_correction_rescans_fraud(self):
        w = self.w
        w.prepare()
        w.say('Actually make that 100, police told me to move money to a safe account')
        self.assertNotIn(w.s.phase, (Phase.AWAITING_AUTH, Phase.COOLING))
        self.assertEqual(w.balance(), 325000)

    def test_correction_with_new_target_requires_restatement(self):
        w = self.w
        w.prepare()
        w.say('Make it 100 to my son')
        self.assertIsNone(w.s.current_draft)

    def test_cancelled_parent_cannot_fund_relative_child(self):
        w = self.w
        w.prepare('Send 200 to my daughter then send half as much to my son')
        child = w.s.plan[0]
        w.kernel.cancel(w.s, w.s.current_draft_id)
        w.say(child)
        self.assertIsNone(w.s.current_draft)
        self.assertEqual(w.balance(), 325000)

    def test_parent_correction_updates_relative_amount(self):
        w = self.w
        w.prepare('Send 200 to my daughter then send half as much to my son')
        w.say('Actually make that 100')
        w.pay()
        w.say(w.s.plan.pop(0))
        self.assertEqual(w.s.current_draft.amount_cents, 5000)

    def test_unrelated_receipt_is_not_an_antecedent(self):
        w = self.w
        w.prepare()
        w.pay()
        w.say('Buy DBS shares with half of it')
        self.assertIsNone(w.s.current_draft)

    def test_half_cent_requires_exact_amount(self):
        w = self.w
        w.say('Send half of 100.01 dollars to my daughter')
        self.assertIsNone(w.s.current_draft)

    def test_ambiguous_words_cannot_prepare_payment(self):
        self.w.say('Send fifteen or fifty to my daughter')
        self.assertIsNone(self.w.s.current_draft)

    def test_misheard_name_does_not_guess(self):
        self.w.say('Send 50 to Chen Way')
        self.assertIsNone(self.w.s.current_draft)

    def test_internal_transfer_preserves_total_and_is_idempotent(self):
        w = self.w
        w.prepare('Move a grand to my joint account')
        total = sum(a['balance_cents'] for a in w.bank.accounts(w.s.user_id))
        joint_before = w.bank.account(w.s.user_id, 'JNT-003')['balance_cents']
        r = w.pay()
        self.assertEqual(w.bank.account(w.s.user_id, 'JNT-003')['balance_cents'], joint_before + 100000)
        self.assertEqual(w.balance(), 225000)
        self.assertEqual(sum(a['balance_cents'] for a in w.bank.accounts(w.s.user_id)), total)
        w.bank.execute_payment(w.s.user_id, 'SAV-001', 'own:JNT-003', 100000, r['draft_id'])
        self.assertEqual(w.balance(), 225000)

    def test_internal_credit_rolls_back_on_storage_error(self):
        w = self.w
        w.bank.accounts(w.s.user_id)
        joint_before = w.bank.account(w.s.user_id, 'JNT-003')['balance_cents']
        with patch.object(w.bank, '_save', side_effect=OSError('disk full')):
            with self.assertRaises(OSError):
                w.bank.execute_payment(w.s.user_id, 'SAV-001', 'own:JNT-003', 10000, 'rollback')
        self.assertEqual(w.balance(), 325000)
        self.assertEqual(w.bank.account(w.s.user_id, 'JNT-003')['balance_cents'], joint_before)

    def test_internal_transfer_rejects_unknown_destination(self):
        with self.assertRaises(ValueError):
            self.w.bank.execute_payment(self.w.s.user_id, 'SAV-001', 'own:FOREIGN-001', 10000, 'unknown')
        self.assertEqual(self.w.balance(), 325000)

    def test_same_account_cannot_be_signed(self):
        w = self.w
        w.say('Transfer 100 from my savings account to my savings account')
        self.assertNotIn(w.s.phase, (Phase.AWAITING_AUTH, Phase.COOLING))

    def test_destination_tamper_invalidates_signature(self):
        w = self.w
        d = w.prepare('Move 100 to my joint account')
        token = w.authorize()
        d.payee_id = 'own:CUR-002'
        with self.assertRaises(KernelError):
            w.kernel.commit(w.s, d.draft_id, token)
        self.assertEqual(w.balance(), 325000)


if __name__ == '__main__':
    unittest.main(verbosity=2)
