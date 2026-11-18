----------------------- MODULE GuardApprovalProofs -----------------------
EXTENDS GuardApproval, TLAPS

DialogProvenance(call) ==
  (call.phase \in {"dialog", "approved"}) =>
    /\ call.source \in (ConfirmSources \cup RetrySources)
    /\ call.retry = (call.source \in RetrySources)
    /\ (call.scope = "remember") => call.source = "confirm-remember"
    /\ (call.phase = "approved") => call.scope \in ApprovalScopes

Invariant == \A id \in Calls : CallSafety(calls[id]) /\ DialogProvenance(calls[id])

THEOREM InitEstablishesInvariant == Init => Invariant
BY SMT DEF Init, Invariant, CallSafety, DialogProvenance, NewCall, CallState, Unchecked

THEOREM NextPreservesInvariant == Invariant /\ [Next]_vars => Invariant'
<1>1 Invariant /\ UNCHANGED vars => Invariant'
  BY SMT DEF Invariant, vars
<1>2 Invariant /\ ExpireTickets => Invariant'
  BY SMT DEF Invariant, ExpireTickets
<1>3 \A id \in Calls :
       Invariant /\ (AutoAllow(id) \/ RejectDialog(id)) => Invariant'
  BY SMT DEF Invariant, CallSafety, DialogProvenance, AutoAllow, RejectDialog,
             ReplaceCall, RespondToCall, NewCall, CallState
<1>4 \A id \in Calls, source \in ConfirmSources, ui \in BOOLEAN :
       Invariant /\ RequestConfirmation(id, source, ui) => Invariant'
  BY SMT DEF Invariant, CallSafety, DialogProvenance, ConfirmSources, RetrySources,
             RequestConfirmation, ReplaceCall, NewCall, CallState
<1>5 \A id \in Calls, key \in RetryKeys, source \in BlockSources, ui, rules \in BOOLEAN :
       Invariant /\ (InitialBlock(id, key, source, ui, rules) \/
                     RequestRetry(id, key, source, ui, rules)) => Invariant'
  BY SMT DEF Invariant, CallSafety, DialogProvenance, InitialBlock, RequestRetry,
             ConfirmSources, RetrySources, ReplaceCall, NewCall, CallState
<1>6 \A id \in Calls, scope \in ApprovalScopes :
       Invariant /\ SubmitApproval(id, scope) => Invariant'
  BY SMT DEF Invariant, CallSafety, DialogProvenance, SubmitApproval,
             ReplaceCall, RespondToCall, CallState
<1>7 \A id \in Calls, checked \in Checks, saved \in BOOLEAN :
       Invariant /\ FinishApproval(id, checked, saved) => Invariant'
  BY SMT DEF Invariant, CallSafety, DialogProvenance, FinishApproval,
             RecheckPassed, ApprovalScopes, ConfirmSources, RetrySources,
             ReplaceCall, RespondToCall, CallState
<1>8 Invariant /\ InvalidateDialogs => Invariant'
  BY SMT DEF Invariant, CallSafety, DialogProvenance, InvalidateDialogs, NewCall, CallState
<1> QED BY <1>1, <1>2, <1>3, <1>4, <1>5, <1>6, <1>7, <1>8 DEF Next

THEOREM SafetyHolds == Spec => []Safety
<1>1 Spec => []Invariant
  BY PTL, InitEstablishesInvariant, NextPreservesInvariant DEF Spec
<1>2 Invariant => Safety
  BY DEF Invariant, Safety
<1> QED BY PTL, <1>1, <1>2

DecisionTransition(id) ==
  ConsumesRetryTicket(id) /\ SavesCheckedApproval(id) /\ DiscardsInvalidatedApproval(id)

THEOREM DecisionDiscipline ==
  [Next]_vars => RetryTransition /\ SaveTransition /\ InvalidatedTransition
<1>1 UNCHANGED vars => \A id \in Calls : DecisionTransition(id)
  BY SMT DEF vars, DecisionTransition, ConsumesRetryTicket, SavesCheckedApproval,
             DiscardsInvalidatedApproval
<1>2 (ExpireTickets \/ InvalidateDialogs) => \A id \in Calls : DecisionTransition(id)
  BY SMT DEF ExpireTickets, InvalidateDialogs, DecisionTransition, ConsumesRetryTicket,
             SavesCheckedApproval, DiscardsInvalidatedApproval, NewCall, CallState
<1>3 \A id \in Calls :
       (AutoAllow(id) \/ RejectDialog(id)) => \A other \in Calls : DecisionTransition(other)
  BY SMT DEF AutoAllow, RejectDialog, Ready, ReplaceCall, RespondToCall,
             NewCall, CallState, DecisionTransition, ConsumesRetryTicket,
             SavesCheckedApproval, DiscardsInvalidatedApproval
<1>4 \A id \in Calls, source \in ConfirmSources, ui \in BOOLEAN :
       RequestConfirmation(id, source, ui) => \A other \in Calls : DecisionTransition(other)
  BY SMT DEF RequestConfirmation, Ready, ReplaceCall, NewCall, CallState,
             DecisionTransition, ConsumesRetryTicket, SavesCheckedApproval,
             DiscardsInvalidatedApproval
<1>5 \A id \in Calls, key \in RetryKeys, source \in BlockSources, ui, rules \in BOOLEAN :
       (InitialBlock(id, key, source, ui, rules) \/ RequestRetry(id, key, source, ui, rules))
         => \A other \in Calls : DecisionTransition(other)
  BY SMT DEF InitialBlock, RequestRetry, Ready, ReplaceCall, NewCall, CallState,
             DecisionTransition, ConsumesRetryTicket, SavesCheckedApproval,
             DiscardsInvalidatedApproval
<1>6 \A id \in Calls, scope \in ApprovalScopes :
       SubmitApproval(id, scope) => \A other \in Calls : DecisionTransition(other)
  BY SMT DEF SubmitApproval, ReplaceCall, RespondToCall, CallState, DecisionTransition,
             ConsumesRetryTicket, SavesCheckedApproval, DiscardsInvalidatedApproval
<1>7 \A id \in Calls, checked \in Checks, saved \in BOOLEAN :
       FinishApproval(id, checked, saved) => \A other \in Calls : DecisionTransition(other)
  BY SMT DEF FinishApproval, ReplaceCall, RespondToCall, CallState, DecisionTransition,
             ConsumesRetryTicket, SavesCheckedApproval, DiscardsInvalidatedApproval
<1> QED BY <1>1, <1>2, <1>3, <1>4, <1>5, <1>6, <1>7
        DEF Next, DecisionTransition, RetryTransition, SaveTransition, InvalidatedTransition

THEOREM DecisionSafetyHolds ==
  Spec => RetryTicketSafety /\ SavedApprovalSafety /\ InvalidatedApprovalSafety
<1>1 [Next]_vars => [RetryTransition]_vars /\ [SaveTransition]_vars /\ [InvalidatedTransition]_vars
  BY DecisionDiscipline
<1> QED BY PTL, <1>1 DEF Spec, RetryTicketSafety, SavedApprovalSafety, InvalidatedApprovalSafety

=============================================================================
