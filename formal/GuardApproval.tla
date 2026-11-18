-------------------------- MODULE GuardApproval --------------------------
\* Models the guarded path of extensions/guard/index.ts (tool_call) and
\* the approval choices in extensions/guard/ui.ts (confirmDialog).
\* Calls are reusable slots for interleaved calls. RetryKeys abstracts the
\* hash of call identity, project, trust, session, and rule versions.
\* Guarded calls stop at the tool_call decision. No tool execution, model
\* accuracy, or atomicity between filesystem observations is assumed.
\* Session and settings invalidation is sticky for dialogs already open.
CONSTANTS Calls, RetryKeys

VARIABLES calls, tickets

vars == <<calls, tickets>>

RetrySources == {"hard-deny", "model-block"}
BlockSources == RetrySources \cup {"rule-deny", "error-block"}
ConfirmSources == {"confirm", "confirm-remember"}
ApprovalScopes == {"once", "remember"}

\* This is the result of the rechecks made after the dialog. A stable
\* snapshot represents the successful input, session ID/dir/epoch, settings,
\* trust, shell, executable, context, and filesystem policy comparisons.
\* An abort signal or failed inspection can be observed at recheck time.
Checks == [
  snapshot : {"stable", "changed", "unavailable", "aborted"},
  denyRule : BOOLEAN,
  hardDeny : {"clear", "same", "different"}
]

CallState(phase, source, key, retry, scope, checked, savedAllow) == [
  phase |-> phase,
  source |-> source,
  key |-> key,
  retry |-> retry,
  scope |-> scope,
  checked |-> checked,
  savedAllow |-> savedAllow
]

Unchecked == [snapshot |-> "unchecked", denyRule |-> FALSE, hardDeny |-> "clear"]

NewCall(phase, source, key, retry) ==
  CallState(phase, source, key, retry, "none", Unchecked, FALSE)

ReplaceCall(id, replacement) ==
  [other \in Calls |-> IF other = id THEN replacement ELSE calls[other]]

RespondToCall(id, phase, scope, checked, savedAllow) ==
  LET current == calls[id]
  IN ReplaceCall(id, CallState(phase, current.source, current.key, current.retry,
                               scope, checked, savedAllow))

Init ==
  /\ calls = [id \in Calls |-> NewCall("idle", "none", "unused", FALSE)]
  /\ tickets = {}

Ready(id) == calls[id].phase \in {"idle", "run", "blocked"}

\* Initial model/static verdicts are abstract inputs. An ordinary allow
\* represents a completed assessment and all applicable pre-dialog checks.
AutoAllow(id) ==
  /\ Ready(id)
  /\ calls' = ReplaceCall(id, NewCall("run", "allow", "unused", FALSE))
  /\ UNCHANGED tickets

InitialBlock(id, key, source, hasUI, rulesAvailable) ==
  /\ Ready(id)
  /\ source \in BlockSources
  /\ LET eligible == source \in RetrySources /\ hasUI /\ rulesAvailable
     IN /\ ~(eligible /\ key \in tickets)
        /\ tickets' = IF eligible THEN tickets \cup {key} ELSE tickets \ {key}
  /\ calls' = ReplaceCall(id, NewCall("blocked", source, key, FALSE))

RequestConfirmation(id, source, hasUI) ==
  /\ Ready(id)
  /\ source \in ConfirmSources
  /\ calls' = ReplaceCall(id,
       NewCall(IF hasUI THEN "dialog" ELSE "blocked", source, "unused", FALSE))
  /\ UNCHANGED tickets

RequestRetry(id, key, source, hasUI, rulesAvailable) ==
  /\ Ready(id)
  /\ source \in RetrySources
  /\ hasUI /\ rulesAvailable
  /\ key \in tickets
  /\ tickets' = tickets \ {key}
  /\ calls' = ReplaceCall(id, NewCall("dialog", source, key, TRUE))

\* Only the user can submit an approval. "remember" combines the scopes
\* that cause an allow-rule insertion attempt.
SubmitApproval(id, scope) ==
  /\ calls[id].phase = "dialog"
  /\ scope \in ApprovalScopes
  /\ scope = "remember" => calls[id].source = "confirm-remember"
  /\ calls' = RespondToCall(id, "approved", scope, Unchecked, FALSE)
  /\ UNCHANGED tickets

\* A lifecycle or settings change invalidates the earlier approval even
\* if the old settings are restored or the UI still delivers a response.
InvalidateDialogs ==
  LET pending == {id \in Calls : calls[id].phase \in {"dialog", "approved"}}
  IN /\ pending /= {}
     /\ calls' = [id \in Calls |->
          IF id \in pending THEN NewCall("invalidated", "none", "unused", FALSE) ELSE calls[id]]
     /\ UNCHANGED tickets

\* Dismissal, denial and discarded stale responses cannot save an allow.
\* Remembered deny rules are abstracted by the denyRule input.
RejectDialog(id) ==
  /\ calls[id].phase \in {"dialog", "invalidated"}
  /\ calls' = RespondToCall(id, "blocked", "none", Unchecked, FALSE)
  /\ UNCHANGED tickets

RecheckPassed(call, checked) ==
  /\ checked.snapshot = "stable"
  /\ ~checked.denyRule
  /\ \/ checked.hardDeny = "clear"
     \/ /\ checked.hardDeny = "same"
        /\ call.retry
        /\ call.source = "hard-deny"

FinishApproval(id, checked, savedAllow) ==
  /\ calls[id].phase = "approved"
  /\ LET passed == RecheckPassed(calls[id], checked)
         \* An eligible save can fail without denying the current call.
     IN /\ savedAllow => (passed /\ calls[id].scope = "remember")
        /\ calls' = RespondToCall(id, IF passed THEN "run" ELSE "blocked",
                                  calls[id].scope, checked, savedAllow)
  /\ UNCHANGED tickets

\* Ticket expiry abstracts capacity eviction and the resets that clear
\* blockedOnce. Dropping an arbitrary subset overapproximates those cases.
ExpireTickets ==
  /\ tickets' \in SUBSET tickets
  /\ UNCHANGED calls

Next ==
  \/ ExpireTickets
  \/ InvalidateDialogs
  \/ \E id \in Calls : AutoAllow(id) \/ RejectDialog(id)
  \/ \E id \in Calls, source \in ConfirmSources, ui \in BOOLEAN :
       RequestConfirmation(id, source, ui)
  \/ \E id \in Calls, key \in RetryKeys, source \in BlockSources,
        ui, rules \in BOOLEAN :
       InitialBlock(id, key, source, ui, rules) \/ RequestRetry(id, key, source, ui, rules)
  \/ \E id \in Calls, scope \in ApprovalScopes : SubmitApproval(id, scope)
  \/ \E id \in Calls, checked \in Checks, saved \in BOOLEAN :
       FinishApproval(id, checked, saved)

Spec == Init /\ [][Next]_vars

\* A successful previously blocked call had a one-time approval for
\* an eligible retry. The rechecks gate every successful dialog outcome.
CallSafety(call) ==
  /\ (call.phase = "run" /\ call.source /= "allow") =>
       /\ call.scope \in ApprovalScopes
       /\ call.checked.snapshot = "stable"
       /\ ~call.checked.denyRule
       /\ (call.checked.hardDeny /= "clear") =>
            /\ call.checked.hardDeny = "same"
            /\ call.source = "hard-deny"
            /\ call.retry
       /\ (call.source \notin ConfirmSources) =>
            /\ call.source \in RetrySources
            /\ call.retry
            /\ call.scope = "once"
  /\ call.savedAllow =>
       /\ call.phase = "run"
       /\ call.source = "confirm-remember"
       /\ call.scope = "remember"
       /\ ~call.retry

Safety == \A id \in Calls : CallSafety(calls[id])

\* A newly opened retry dialog can only come from a matching ticket,
\* and the transition consumes that ticket before any user response.
ConsumesRetryTicket(id) ==
  (calls[id].phase /= "dialog" /\ calls'[id].phase = "dialog" /\ calls'[id].retry) =>
    /\ calls'[id].key \in tickets
    /\ tickets' = tickets \ {calls'[id].key}

RetryTransition == \A id \in Calls : ConsumesRetryTicket(id)

RetryTicketSafety == [][RetryTransition]_vars

\* The transition that retains an allow rule must consume a live approval
\* for remembering it and must pass the same recheck that gates execution.
SavesCheckedApproval(id) ==
  (~calls[id].savedAllow /\ calls'[id].savedAllow) =>
    /\ calls[id].phase = "approved"
    /\ calls[id].scope = "remember"
    /\ RecheckPassed(calls[id], calls'[id].checked)

SaveTransition == \A id \in Calls : SavesCheckedApproval(id)

SavedApprovalSafety == [][SaveTransition]_vars

DiscardsInvalidatedApproval(id) ==
  calls[id].phase = "invalidated" => calls'[id].phase \in {"invalidated", "blocked"}

InvalidatedTransition == \A id \in Calls : DiscardsInvalidatedApproval(id)

InvalidatedApprovalSafety == [][InvalidatedTransition]_vars

=============================================================================
