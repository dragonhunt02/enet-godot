%% src/dtls_echo_server.erl
-module(dtls_echo_server).
-behaviour(gen_server).

-export([start_link/2]).
-export([init/1, handle_info/2, handle_cast/2, handle_call/3, terminate/2, code_change/3]).
%% handle_continue/2, 

-record(state, {
  transport,
  raw_socket,
  is_socket_owned = true,
  socket = undefined,
  peername = undefined
}).

%%% Called via dtls_echo_conn_sup:start_child(Transport, Socket)
start_link(Transport, RawSocket) ->
    gen_server:start_link(?MODULE, {Transport, RawSocket}, []).

init({Transport, RawSocket}) ->
    process_flag(trap_exit, true),
    io:format("Init echo server socket ~p~n", [RawSocket]),

    %% Store raw args and defer the actual wait() to handle_continue
    State0 = #state{transport = Transport,
                    raw_socket = RawSocket},
    gen_server:cast(self(), {handshake}),
    {ok, State0}. %%, {continue, handshake}}.


%%handle_continue(handshake, State0 = #state{transport=Transport, socket=RawSocket}) ->
handle_cast({handshake}, State0 = #state{transport=Transport, raw_socket=RawSocket}) ->
        io:format("Echo server handshake socket ~p~n", [RawSocket]),
    %% Upgrade the raw socket to a DTLS session
    case Transport:wait(RawSocket) of
      {ok, Socket} ->
        io:format("Echo server trandport ok socket ~p~n", [Socket]),
        {ok, PeerName} = Transport:peername(Socket),
        {ok, {SockIP, SockPort}} = Transport:sockname(Socket),
        io:format("Print port ~p:~p~n", [SockIP, SockPort]),
        
        Host = gproc:where({n, l, {enet_host, SockPort}}), %%AssignedPort
        IsSocketOwned = case enet_host:give_socket(Host, Socket, Transport) of
            {ok, _} -> false;
            {error, Reason2} -> 
                            io:format("Failed to give socket control to process: ~p.~n~p", [Host, Reason2]),
                            true
        end,
        State = State0#state{socket=Socket, peername=PeerName, is_socket_owned=IsSocketOwned},
        %%enet_host:give_socket(Host, Socket, Transport),
        {stop, normal, State};
        %% {noreply, State};
      {error, Reason1} ->
        io:format("Echo server transport fail reason ~p~n", [Reason1]),
        %%Transport:fast_close(RawSocket),
        {stop, {handshake_failed, Reason1}, State0}
        %%{stop, {wait_error, Reason}}
    end;

handle_cast(_Msg, State) ->
    %% No action taken; just continue
    {noreply, State}.

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

handle_call(_Request, _From, State) ->
    %% Respond with a default reply
    {reply, ok, State}.

terminate(_Reason, #state{transport = T, raw_socket = RawSocket, socket = undefined}) ->
    %% Failed to upgrade raw_socket, close
    T:fast_close(RawSocket),
    ok;
terminate(_Reason, #state{transport = T, socket = Socket, is_socket_owned = true}) ->
    %% Failed to give socket control, close
    T:fast_close(Socket),
    ok;
terminate(_Reason, #state{transport = T, socket = Socket, is_socket_owned = false}) ->
    %% Socket control handed off, so don't manage it
    ok;
terminate(Reason, State) ->
    %% Invalid Unexpected State
    io:format("Invalid state on terminate/2: ~p~n", [Reason]),
    unknown.

code_change(_Old, State, _Extra) ->
    {ok, State}.
