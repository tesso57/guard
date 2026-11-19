----------------------- MODULE GuardApprovalDialog -----------------------
\* One confirmDialog invocation (extensions/guard/ui.ts). Parameters are
\* fixed at entry. The label flags stand for truthy rendered labels.
\* Tokens represent distinct rendered labels, except for the scope labels
\* shared by both submenus. "cancel" means ui.select returned no selection;
\* "other" represents any string outside the modeled labels.
\* Each response belongs to the current ui.select invocation. The UI
\* adapter, label rendering, and rejected promises are outside the model.
\* Only the returned decision/scope is modeled, up to the caller's recheck.

VARIABLES config, dialog
vars == <<config, dialog>>

Configurations == [
  allowLabel : BOOLEAN, denyLabel : BOOLEAN,
  rememberAllow : BOOLEAN, globalAllow : BOOLEAN
]

MainItems ==
  {"allow-once", "deny-once"}
    \cup (IF config.allowLabel /\ config.rememberAllow
          THEN {"allow-session", IF config.globalAllow THEN "open-allow" ELSE "allow-project"}
          ELSE {})
    \cup (IF config.denyLabel THEN {"open-deny"} ELSE {})

ScopeScreens == {"allow-scope", "deny-scope"}
SelectScreens == {"main"} \cup ScopeScreens

Offered(screen) ==
  CASE screen = "main" -> MainItems
    [] screen = "allow-scope" -> {"project", "global", "back"}
    [] screen = "deny-scope" -> {"session", "project", "global", "back"}
    [] OTHER -> {}

Replies == {
  "allow-once", "allow-session", "allow-project", "open-allow", "deny-once", "open-deny",
  "session", "project", "global", "back", "cancel", "other"
}

Result(decision, scope) == [decision |-> decision, scope |-> scope]
NoResult == Result("none", "none")
Pick(screen, item) == [screen |-> screen, item |-> item]
NoPick == Pick("none", "none")

State(screen, result, origin, pendingScope) == [
  screen |-> screen, result |-> result, origin |-> origin, pendingScope |-> pendingScope
]

Menu(screen) == State(screen, NoResult, NoPick, "none")
Start == Menu("main")
Finish(result, origin) == State("done", result, origin, "none")
AskReason(scope, origin) == State("deny-reason", NoResult, origin, scope)

MainReply(item) ==
  LET origin == Pick("main", item)
  IN IF item \notin Offered("main") THEN Finish(Result("deny", "once"), origin)
     ELSE IF item = "allow-once" THEN Finish(Result("allow", "once"), origin)
     ELSE IF item = "allow-session" THEN Finish(Result("allow", "session"), origin)
     ELSE IF item = "allow-project" THEN Finish(Result("allow", "project"), origin)
     ELSE IF item = "open-allow" THEN Menu("allow-scope")
     ELSE IF item = "open-deny" THEN Menu("deny-scope")
     ELSE AskReason("once", origin)

ScopeReply(screen, item) ==
  LET origin == Pick(screen, item)
  IN IF item \notin Offered(screen) THEN Finish(Result("deny", "once"), origin)
     ELSE IF item = "back" THEN Start
     ELSE IF screen = "allow-scope" THEN Finish(Result("allow", item), origin)
     ELSE AskReason(item, origin)

Init ==
  /\ config \in Configurations
  /\ dialog = Start

SelectMain(item) ==
  /\ dialog.screen = "main"
  /\ dialog' = MainReply(item)

SelectScope(item) ==
  /\ dialog.screen \in ScopeScreens
  /\ dialog' = ScopeReply(dialog.screen, item)

\* The optional text annotates the denial. Closing that prompt retains
\* the scope already chosen in a menu, including a remembered denial.
ReasonReplies == {"text", "cancel"}

FinishReason(reply) ==
  /\ dialog.screen = "deny-reason"
  /\ reply \in ReasonReplies
  /\ dialog' = Finish(Result("deny", dialog.pendingScope), dialog.origin)

Next ==
  /\ UNCHANGED config
  /\ \/ \E item \in Replies : SelectMain(item) \/ SelectScope(item)
     \/ \E reply \in ReasonReplies : FinishReason(reply)

Spec == Init /\ [][Next]_vars

\* Independently state which user selection licenses each explicit result.
\* The same "global" or "project" label has a different effect by screen.
AllowChoices == {
  <<"main", "allow-once", "once">>,
  <<"main", "allow-session", "session">>,
  <<"main", "allow-project", "project">>,
  <<"allow-scope", "project", "project">>,
  <<"allow-scope", "global", "global">>
}

DenyChoices == {
  <<"main", "deny-once", "once">>,
  <<"deny-scope", "session", "session">>,
  <<"deny-scope", "project", "project">>,
  <<"deny-scope", "global", "global">>
}

ExplicitDeny(origin, scope) ==
  /\ origin.screen \in SelectScreens
  /\ origin.item \in Offered(origin.screen)
  /\ <<origin.screen, origin.item, scope>> \in DenyChoices
  /\ (origin.screen = "deny-scope" => "open-deny" \in MainItems)

MatchesSelection(state) ==
  LET origin == state.origin
      result == state.result
  IN /\ origin.screen \in SelectScreens
     /\ CASE result.decision = "allow" ->
               /\ origin.item \in Offered(origin.screen)
               /\ <<origin.screen, origin.item, result.scope>> \in AllowChoices
               /\ (origin.screen = "allow-scope" => "open-allow" \in MainItems)
           [] result.decision = "deny" ->
               \/ ExplicitDeny(origin, result.scope)
               \/ /\ origin.item \in Replies \ Offered(origin.screen)
                  /\ result.scope = "once"
           [] OTHER -> FALSE

DialogInvariant ==
  CASE dialog.screen = "main" -> dialog = Start
    [] dialog.screen = "allow-scope" ->
         /\ "open-allow" \in MainItems
         /\ dialog = Menu("allow-scope")
    [] dialog.screen = "deny-scope" ->
         /\ "open-deny" \in MainItems
         /\ dialog = Menu("deny-scope")
    [] dialog.screen = "deny-reason" ->
         /\ dialog.result = NoResult
         /\ ExplicitDeny(dialog.origin, dialog.pendingScope)
    [] dialog.screen = "done" -> MatchesSelection(dialog)
    [] OTHER -> FALSE

\* Tie the recorded origin and the next screen to the actual select reply.
\* Back rebuilds the main screen with no pending or final choice.
FollowsReply(item) ==
  /\ (dialog'.screen \in {"done", "deny-reason"}) =>
       dialog'.origin = Pick(dialog.screen, item)
  /\ (dialog'.screen = "allow-scope") => dialog.screen = "main" /\ item = "open-allow"
  /\ (dialog'.screen = "deny-scope") => dialog.screen = "main" /\ item = "open-deny"
  /\ (dialog'.screen = "main") => dialog.screen \in ScopeScreens /\ item = "back"
  /\ (dialog.screen \in ScopeScreens /\ item = "back") => dialog' = Start
  /\ (item \notin Offered(dialog.screen)) =>
       /\ dialog'.screen = "done"
       /\ dialog'.result = Result("deny", "once")

ReplyCorrespondence ==
  /\ \A item \in Replies : (SelectMain(item) \/ SelectScope(item)) => FollowsReply(item)
  /\ \A reply \in ReasonReplies :
       FinishReason(reply) =>
         /\ dialog'.origin = dialog.origin
         /\ dialog'.result = Result("deny", dialog.pendingScope)

ReplySafety == [][ReplyCorrespondence]_vars

=============================================================================
