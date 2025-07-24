%% src/dtls_echo_server.erl
-module(dtls_echo_server).
-behaviour(gen_statem).

-include("enet_peer.hrl").
-include("enet_commands.hrl").
-include("enet_protocol.hrl").

-export([start_link/5]).
%%-export([handle_info/2]).
%%-export([init/1, handle_info/2, handle_cast/2, handle_call/3, terminate/2, code_change/3]).
%% handle_continue/2, 
%%--------------------------------------------------------------------
%% gen_statem callbacks
%%--------------------------------------------------------------------
-export([
  callback_mode/0,
  init/1,
  handshake/3,
  socket_handoff/3,
  connected/3,
  terminate/3,
  code_change/4
]).

-record(state, {
  transport,
  raw_socket,
  is_socket_owned = true,
  socket = undefined,
  peername = undefined
}).

-define(NULL_PEER_ID, ?MAX_PEER_ID).

%%% Called via dtls_echo_conn_sup:start_child(Transport, Socket)
start_link(AssignedPort, ConnectFun, Options, Transport, RawSocket) ->
    gen_statem:start_link(?MODULE, {AssignedPort, ConnectFun, Options, Transport, RawSocket}, []).

%%--------------------------------------------------------------------
%% Callback Mode
%%--------------------------------------------------------------------
callback_mode() -> state_functions.

init({AssignedPort, ConnectFun, Options, Transport, RawSocket}) ->
    process_flag(trap_exit, true),
    io:format("Init echo server socket ~p~n", [RawSocket]),
    Ref = make_ref(),
    gproc:reg({n, l, {enet_demux_peer, Ref}}),
    gproc:reg({p, l, name}, Ref),
    gproc:reg({p, l, port}, AssignedPort),
    %%gproc:reg({p, l, peer_id}, PeerID),

    %% Store raw args and defer the actual wait() to handle_continue
    State0 = #state{transport = Transport,
                    raw_socket = RawSocket},
    {ok, handshake, State0, [{next_event, internal, exec}]}.
    %%gen_server:cast(self(), {handshake}),
    %%{ok, State0}. %%, {continue, handshake}}.

%%handle_continue(handshake, State0 = #state{transport=Transport, socket=RawSocket}) ->
%%handle_cast({handshake}, State0 = #state{transport=Transport, raw_socket=RawSocket}) ->
handshake(info, {'EXIT', From, Reason}, State) ->
    %% transport or socket died unexpectedly
    io:format("handshake - trapped exit from ~p: ~p~n", [From, Reason]),
    {stop, Reason, State};
handshake(internal, exec, State0 = #state{transport=Transport, raw_socket=RawSocket}) ->
    io:format("Echo server handshake socket ~p~n", [RawSocket]),
    %% Upgrade the raw socket to a DTLS session
    case Transport:wait(RawSocket) of
      {ok, Socket} ->
        io:format("Echo server trandport ok socket ~p~n", [Socket]),
        {ok, PeerName} = Transport:peername(Socket),
        State = State0#state{socket=Socket, peername=PeerName},
        %%{next_state, socket_handoff, State, [{next_event, internal, exec}]};
        {next_state, connected, State};
      {error, Reason} ->
        io:format("Echo server transport fail reason ~p~n", [Reason]),
        %%Transport:fast_close(RawSocket),
        {stop, {handshake_failed, Reason}, State0}
        %%{stop, {wait_error, Reason}}
    end.

socket_handoff(info, {'EXIT', From, Reason}, State) ->
    %% transport or socket died unexpectedly
    io:format("socket_handoff - trapped exit from ~p: ~p~n", [From, Reason]),
    {stop, Reason, State};
socket_handoff(internal, _Any, State0 = #state{transport=Transport, socket=Socket}) ->
    io:format("Echo server handoff socket ~p~n", [Socket]),
    {ok, {SockIP, SockPort}} = Transport:sockname(Socket),
    io:format("Print port ~p:~p~n", [SockIP, SockPort]),   
    Host = gproc:where({n, l, {enet_host, SockPort}}), %%AssignedPort
    case enet_host:give_socket(Host, Socket, Transport) of
        {ok, _} ->
                  State = State0#state{is_socket_owned=false},
                  {stop, normal, State};
                  %%{keep_state, State};
        {error, Reason} -> 
                        io:format("Failed to give socket control to process: ~p.~n~p", [Host, Reason]),
                        {stop, {handoff_failed, Reason}, State0}
    end.
    %%State = State0#state{socket=Socket, peername=PeerName, is_socket_owned=IsSocketOwned},
    %%{stop, normal, State};
 

%%% Handle all DTLS/SSL messages
connected(info, {ssl, _Raw, Packet}, State = #state{transport=T, socket=Socket, peername=P}) ->
    io:format("~s ← ~p~n", [esockd:format(P), Packet]),
    %%T:async_send(Socket, Packet),
    {PeerIP, PeerPort} = P,
    demux_packet(PeerIP, PeerPort, Packet, State),
    {keep_state, State};

connected(info, {ssl_passive, _Raw}, State = #state{transport=T, socket=S, peername=P}) ->
    io:format("~s → passive~n", [esockd:format(P)]),
    T:setopts(S, [{active, 100}]),
    {keep_state, State};

connected(info, {inet_reply, _Raw, ok}, State) ->
    {keep_state, State};

connected(info, {ssl_closed, _Raw}, State) ->
    {stop, normal, State};

connected(info, {ssl_error, _Raw, Reason}, State = #state{peername=P}) ->
    io:format("~s error: ~p~n", [esockd:format(P), Reason]),
    {stop, Reason, State};

connected(info, _Other, State) ->
    {keep_state, State}.

%% Terminate
terminate(_Reason, handshake, #state{transport = T, raw_socket = RawSocket, socket = undefined}) ->
    %% Failed to upgrade raw_socket, close
    T:fast_close(RawSocket),
    ok;
terminate(_Reason, socket_handoff, #state{transport = T, socket = Socket, is_socket_owned = true}) ->
    %% Failed to give socket control, close
    T:fast_close(Socket),
    ok;
terminate(_Reason, socket_handoff, #state{transport = T, socket = Socket, is_socket_owned = false}) ->
    %% Socket control handed off, so don't manage it
    ok;
terminate(Reason, _StateName, State) ->
    %% Invalid Unexpected State
    io:format("Invalid state on terminate/3: ~p~n~p~n", [State, Reason]),
    unknown.

code_change(_Old, _StateName, State, _Extra) ->
    {ok, State}.



%% Internal 
demux_packet(IP, Port, Packet, S) ->
    %%
    %% Received a UDP packet.
    %%
    %% - Unpack the ENet protocol header
    %% - Decompress the remaining packet if necessary
    %% - Send the packet to the peer (ID in protocol header)
    %%
    #state{
        socket = Socket,
        compressor = CompressionMode,
        connect_fun = ConnectFun
    } = S,
    %% TODO: Replace call to enet_protocol_decode with binary pattern match.
    {ok,
        #protocol_header{
            compressed = IsCompressed,
            peer_id = RecipientPeerID,
            sent_time = SentTime
        },
        Rest} = enet_protocol_decode:protocol_header(Packet),
    Commands =
        case IsCompressed of
            0 -> Rest;
            1 -> decompress(Rest, CompressionMode)
        end,
    LocalPort = get_port(self()),
    case RecipientPeerID of
        ?NULL_PEER_ID ->
            %% No particular peer is the receiver of this packet.
            %% Create a new peer.
            Ref = make_ref(),
            try enet_pool:add_peer(LocalPort, Ref) of
                PeerID ->
                    Peer = #enet_peer{
                        handshake_flow = remote,
                        peer_id = PeerID,
                        ip = IP,
                        port = Port,
                        name = Ref,
                        host = self(),
                        connect_fun = ConnectFun
                    },
                    gproc:reg({p, l, peer_id}, PeerID),
                    gproc:reg({p, l, peer_name}, Ref),
                    {ok, Pid} = start_peer(Peer),
                    enet_peer:recv_incoming_packet(Pid, IP, SentTime, Commands)
            catch
                error:pool_full -> {error, reached_peer_limit};
                error:exists -> {error, exists}
            end;
        PeerID ->
            CurrentPeerID = get_peer_id(self()),
            case PeerID =:= CurrentPeerID  of
                true -> 
                    case enet_pool:pick_peer(LocalPort, CurrentPeerID) of
                        false ->
                            ok; %% Peer process failed?
                        Pid ->
                            enet_peer:recv_incoming_packet(Pid, IP, SentTime, Commands)
                    end;
                _ -> ok %% Drop invalid/malicious packet attempt
            end
    end.

%%get_next_peer_id() ->
    %% TODO: Replace with random unique 12bit uint excluding 16#FFF 
%%    make_ref().

get_name(Pid) ->
    gproc:get_value({p, l, name}, Pid).

get_peer_name(Peer) ->
    gproc:get_value({p, l, peer_name}, Peer).

get_peer_id(Peer) ->
    gproc:get_value({p, l, peer_id}, Peer).

get_time() ->
    erlang:system_time(1000) band 16#FFFF.

start_peer(Peer = #enet_peer{name = Ref}) ->
    LocalPort = gproc:get_value({p, l, port}, self()),
    PeerSup = gproc:where({n, l, {enet_peer_sup, LocalPort}}),
    {ok, Pid} = enet_peer_sup:start_peer(PeerSup, Peer),
    _Ref = gproc:monitor({n, l, {enet_peer, Ref}}),
    {ok, Pid}.

decompress(Data, zlib) -> 
    zlib:uncompress(Data);
decompress(_Data, Mode) ->
    unsupported_compress_mode(Mode).

compress(Data, zlib) ->
    zlib:compress(Data);
compress(_Data, Mode) ->
    unsupported_compress_mode(Mode).

unsupported_compress_mode(Mode) -> 
    logger:error("Unsupported compression mode: ~p", [Mode]).
