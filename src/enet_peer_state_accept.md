%% state_idle.erl
-module(enet_peer_state_accept).
-behaviour(enet_state_behaviour).

-export([handle/3]).

handle({call, From, start}, _Content, Data) ->
    %% transition into processing
    From ! {reply, ok},
    {next_state, processing, Data};
handle(_, _, Data) ->
    {next_state, idle, Data}.
