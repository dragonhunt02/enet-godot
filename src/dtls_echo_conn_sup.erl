%% src/dtls_echo_conn_sup.erl
-module(dtls_echo_conn_sup).
-behaviour(supervisor).

-export([start_link/0, init/1, start_child/2]).

start_link(_Port, _ConnectFun, _Options) ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

init([]) ->
    %% Each connection is a dtls_echo_server child
    ConnChild = {
      dtls_conn,
      {dtls_echo_server, start_link, []},
      transient,
      5000,
      worker,
      [dtls_echo_server]
    },

    {ok, {{simple_one_for_one, 5, 10}, [ConnChild]}}.

%% Called by listener when a new socket arrives
start_child(Transport, Socket) ->
    supervisor:start_child(?MODULE, [Transport, Socket]).
