-------------------- MODULE GuardApprovalDialogProofs ---------------------
EXTENDS GuardApprovalDialog, TLAPS

THEOREM InitEstablishesInvariant == Init => DialogInvariant
BY SMT DEF Init, DialogInvariant, Start, Menu, State

THEOREM NextPreservesInvariant == DialogInvariant /\ [Next]_vars => DialogInvariant'
<1>1 DialogInvariant /\ UNCHANGED vars => DialogInvariant'
  BY SMT DEF vars, DialogInvariant, MatchesSelection, ExplicitDeny, Offered, MainItems
<1>2 \A item \in Replies :
       DialogInvariant /\ UNCHANGED config /\ SelectMain(item) => DialogInvariant'
  BY SMT DEF SelectMain, MainReply, MainItems, DialogInvariant, MatchesSelection,
             ExplicitDeny, Offered, SelectScreens, ScopeScreens, AllowChoices,
             DenyChoices, Start, Menu, State, Finish, AskReason, Result, Pick
<1>3 \A item \in Replies :
       DialogInvariant /\ UNCHANGED config /\ SelectScope(item) => DialogInvariant'
  BY SMT DEF SelectScope, ScopeReply, ScopeScreens, DialogInvariant, MatchesSelection,
             ExplicitDeny, Offered, MainItems, SelectScreens, AllowChoices, DenyChoices,
             Start, Menu, State, Finish, AskReason, Result, Pick
<1>4 \A reply \in ReasonReplies :
       DialogInvariant /\ UNCHANGED config /\ FinishReason(reply) => DialogInvariant'
  BY SMT DEF DialogInvariant, MatchesSelection, ExplicitDeny, DenyChoices,
             Offered, MainItems, SelectScreens, ScopeScreens, FinishReason, Finish, State, Result
<1> QED BY <1>1, <1>2, <1>3, <1>4 DEF Next

THEOREM ReturnedChoiceFidelity == Spec => []DialogInvariant
BY PTL, InitEstablishesInvariant, NextPreservesInvariant DEF Spec

THEOREM BackReturnsToStart == SelectScope("back") => dialog' = Start
BY SMT DEF SelectScope, ScopeReply, ScopeScreens, Offered

THEOREM CancellingSelectionDeniesOnce ==
  (SelectMain("cancel") \/ SelectScope("cancel")) =>
    /\ dialog'.screen = "done"
    /\ dialog'.result = Result("deny", "once")
BY SMT DEF SelectMain, SelectScope, MainReply, ScopeReply, ScopeScreens, MainItems,
           Offered, Finish, State

THEOREM DismissingReasonKeepsDenial ==
  DialogInvariant /\ FinishReason("cancel") =>
    /\ dialog'.screen = "done"
    /\ dialog'.result = Result("deny", dialog.pendingScope)
    /\ ExplicitDeny(dialog'.origin, dialog'.result.scope)
BY SMT DEF DialogInvariant, FinishReason, Finish, State, Result

THEOREM RepliesRespectCorrespondence == ReplyCorrespondence
<1>1 \A item \in Replies : SelectMain(item) => FollowsReply(item)
  <2>1 \A item \in Replies : SelectMain(item) =>
         /\ dialog.screen = "main"
         /\ dialog'.screen /= "main"
    BY SMT DEF SelectMain, MainReply, Menu, Finish, AskReason, State
  <2>2 \A item \in Replies : SelectMain(item) =>
         (dialog'.screen \in {"done", "deny-reason"}) =>
           dialog'.origin = Pick("main", item)
    BY SMT DEF SelectMain, MainReply, Menu, Finish, AskReason, State
  <2>3 \A item \in Replies : SelectMain(item) =>
         /\ (dialog'.screen = "allow-scope") => item = "open-allow"
         /\ (dialog'.screen = "deny-scope") => item = "open-deny"
    BY SMT DEF SelectMain, MainReply, Menu, Finish, AskReason, State
  <2>4 \A item \in Replies : SelectMain(item) /\ item \notin Offered("main") =>
         /\ dialog'.screen = "done"
         /\ dialog'.result = Result("deny", "once")
    BY SMT DEF SelectMain, MainReply, Finish, State
  <2> QED BY SMT, <2>1, <2>2, <2>3, <2>4 DEF FollowsReply, ScopeScreens
<1>2 \A item \in Replies : SelectScope(item) => FollowsReply(item)
  BY SMT DEF FollowsReply, SelectScope, ScopeScreens, ScopeReply, Start, Menu,
             Offered, Finish, State, Result, Pick, AskReason
<1>3 \A reply \in ReasonReplies :
       FinishReason(reply) =>
         /\ dialog'.origin = dialog.origin
         /\ dialog'.result = Result("deny", dialog.pendingScope)
  BY SMT DEF FinishReason, Finish, State
<1> QED BY <1>1, <1>2, <1>3 DEF ReplyCorrespondence

THEOREM ReplySafetyHolds == Spec => ReplySafety
<1>1 [Next]_vars => [ReplyCorrespondence]_vars
  BY RepliesRespectCorrespondence
<1> QED BY PTL, <1>1 DEF Spec, ReplySafety

=============================================================================
