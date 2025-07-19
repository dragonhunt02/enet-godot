%% src/dtls_echo_listener.erl
-module(dtls_echo_listener).
-behaviour(gen_server).

-export([start_link/3]).
-export([init/1, handle_info/2, handle_cast/2, handle_call/3, terminate/2, code_change/3]).

-record(state, {
  port
}).

%%% API
start_link(Port, _ConnectFun, _Options) ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, Port, []).

%%% gen_server callbacks
init(Port) ->
    ok = esockd:start(),
    PrivDir = code:priv_dir(esockd),
    DtlsOpts = [
      {mode, binary}, {reuseaddr, true}, {active, 100},
      {certfile, filename:join(PrivDir, "cert.pem")}, %%"demo.crt")},
      {keyfile,  filename:join(PrivDir, "key.pem")} %%"demo.key")}
    ],
    Opts = [
      {acceptors, 4},
      {max_connections, 1000},
      {dtls_options, DtlsOpts}
    ],

    %% Tell esockd to use our connection‐sup to spawn each handler
    MFArgs = {dtls_echo_conn_sup, start_child, [Port]},
    {ok, _ListenSock} = esockd:open_dtls('echo/dtls', Port, Opts, MFArgs),

    {ok, #state{port=Port}}.

handle_info(_Info, State) ->
    %% We don’t expect “normal” messages here
    {noreply, State}.

handle_cast(_Msg, State) ->
    %% No action taken; just continue
    {noreply, State}.

handle_call(_Request, _From, State) ->
    %% Respond with a default reply
    {reply, ok, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.
