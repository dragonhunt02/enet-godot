%% enet_state_behaviour.erl
-module(enet_state_behaviour).

-include_lib("stdlib/include/gen_statem.hrl").
-import_type(gen_statem, [state_callback_result/1]).

-callback handle(EventType   :: term(),
                EventContent :: term(),
                StateData    :: term())
       -> state_callback_result(gen_statem:transition_action()).
