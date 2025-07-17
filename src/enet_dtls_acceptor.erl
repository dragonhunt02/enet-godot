-module(enet_dtls_acceptor).
-behaviour(gen_server).

%% API
-export([start_link/3]).

%% callbacks
-export([init/1, handle_info/2, terminate/2, code_change/3]).

-record(state, { listen_sock :: ssl:sslsocket(), port :: inet:port_number(),
                 connect_fun :: fun((ssl:sslsocket()) -> any()), opts :: list() }).

start_link(Port, ConnectFun, Options) ->
    gen_server:start_link(
      {local, {enet_dtls_acceptor, Port}},
      ?MODULE,
      [Port, ConnectFun, Options],
      []
    ).

init([Port, ConnectFun, Options]) ->
    ok = ssl:start(),
    SslOpts = Options ++
      [ {protocol,  dtlsv1_2},
        {reuseaddr, true},
        {active,    false},
        {verify,    verify_none}
      ],
    {ok, ListenSock} = ssl:listen(Port, SslOpts),
    {ok, {{_Addr, AssignedPort}, _}} = inet:sockname(ListenSock),

    %% register for lookup & pub/sub
    gproc:reg({n, l, {enet_host, AssignedPort}}),

    %% kick off the accept loop
    self() ! accept,
    {ok, #state{listen_sock=ListenSock, port=AssignedPort,
                connect_fun=ConnectFun, opts=Options}}.

handle_info(accept, State=#state{listen_sock=LS, port=P, connect_fun=F}) ->
    spawn_link(fun() -> accept_loop(LS, P, F) end),
    {noreply, State};
handle_info(_, State) ->
    {noreply, State}.

terminate(_R, #state{listen_sock=Sock}) ->
    ssl:close(Sock),
    ok.

code_change(_, State, _) -> {ok, State}.

%%--------------------------------------------------------------------
accept_loop(ListenSock, Port, ConnectFun) ->
    case ssl:transport_accept(ListenSock) of
      {ok, SessionSock} ->
        case ssl:handshake(SessionSock, [], 5000) of
          ok ->
            %% spawn a supervised DTLS worker
            {ok, Pid} = supervisor:start_child(
                           {enet_host_sup, Port},
                           [SessionSock]
                         ),
            ssl:controlling_process(SessionSock, Pid),
            %% notify watchers
            gproc:send({n, l, {enet_host, Port}},
                       {new_dtls_connection, Port, SessionSock}),
            ConnectFun(SessionSock);
          {error, Reason} ->
            io:format("DTLS handshake failed: ~p~n", [Reason]),
            ssl:close(SessionSock)
        end,
        accept_loop(ListenSock, Port, ConnectFun);
      {error, closed} ->
        io:format("DTLS listener closed on port ~p~n", [Port]);
      {error, Reason} ->
        io:format("DTLS accept error ~p on port ~p, retrying~n",
                  [Reason, Port]),
        timer:sleep(500),
        accept_loop(ListenSock, Port, ConnectFun)
    end.
