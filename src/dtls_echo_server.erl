%% src/dtls_echo_server.erl
-module(dtls_echo_server).
-behaviour(gen_server).

-export([start_link/2]).
-export([init/1, handle_continue/2, handle_info/2, handle_cast/2, handle_call/3, terminate/2, code_change/3]).

-record(state, {
  transport,
  socket,
  peername
}).

%%% Called via dtls_echo_conn_sup:start_child(Transport, Socket)
start_link(Transport, RawSocket) ->
    gen_server:start_link(?MODULE, {Transport, RawSocket}, []).

init({Transport, RawSocket}) ->
    process_flag(trap_exit, true),
    io:format("Init echo server socket ~p~n", [RawSocket]),

    %% Store raw args and defer the actual wait() to handle_continue
    State0 = #state{transport = Transport,
                    socket    = RawSocket,
                    peername  = undefined},
    {ok, State0, {continue, handshake}}.


handle_continue(handshake, State0 = #state{transport=Transport, socket=RawSocket}) ->
        io:format("Echo server handshake socket ~p~n", [RawSocket]),
    %% Upgrade the raw socket to a DTLS session
    case Transport:wait(RawSocket) of
      {ok, Socket} ->
        io:format("Echo server trandport ok socket ~p~n", [Socket]),
        {ok, {IP, Port} = Peer} = Transport:sockname(Socket),
        io:format("Print port ~p:~p~n", [IP, Port]),
        State = State0#state{socket=Socket, peername=Peer},
        Host = gproc:where({n, l, {enet_host, 7777}}), %%AssignedPort
        enet_host:give_socket(Host, Socket, Transport),
        {stop, normal, State};
        %% {noreply, State};
      {error, Reason} ->
        io:format("Echo server transport fail reason ~p~n", [Reason]),
        Transport:fast_close(RawSocket),
        {stop, {handshake_failed, Reason}, State0}
        %%{stop, {wait_error, Reason}}
    end.

%%% Handle all DTLS/SSL messages
handle_info({ssl, _Raw, Packet}, State = #state{transport=T, socket=S, peername=P}) ->
    io:format("~s ← ~p~n", [esockd:format(P), Packet]),
    T:async_send(S, Packet),
    {noreply, State};

handle_info({ssl_passive, _Raw}, State = #state{transport=T, socket=S, peername=P}) ->
    io:format("~s → passive~n", [esockd:format(P)]),
    T:setopts(S, [{active, 100}]),
    {noreply, State};

handle_info({inet_reply, _Raw, ok}, State) ->
    {noreply, State};

handle_info({ssl_closed, _Raw}, State) ->
    {stop, normal, State};

handle_info({ssl_error, _Raw, Reason}, State = #state{peername=P}) ->
    io:format("~s error: ~p~n", [esockd:format(P), Reason]),
    {stop, Reason, State};

handle_info({'EXIT', _From, _Reason}, State) ->
    %% transport or socket died unexpectedly
    {stop, normal, State};

handle_info(_, State) ->
    {noreply, State}.

handle_cast(_Msg, State) ->
    %% No action taken; just continue
    {noreply, State}.

handle_call(_Request, _From, State) ->
    %% Respond with a default reply
    {reply, ok, State}.

terminate(_Reason, #state{transport=T, socket=S}) ->
    T:fast_close(S),
    ok.

code_change(_Old, State, _Extra) ->
    {ok, State}.
