%% src/dtls_echo_server.erl
-module(dtls_echo_server).
-behaviour(gen_statem).
%%-module(enet_host).
%%-behaviour(gen_server).

-include("enet_peer.hrl").
-include("enet_commands.hrl").
-include("enet_protocol.hrl").

%% API
-export([
    socket_options/0,
    give_socket/3,
    connect/5,
    send_outgoing_commands/4,
    send_outgoing_commands/5,
    get_port/1,
    get_incoming_bandwidth/1,
    get_outgoing_bandwidth/1,
    get_mtu/1,
    get_channel_limit/1
]).

-define(NULL_PEER_ID, ?MAX_PEER_ID).

-export([start_link/2]).
%%-export([init/1, handle_info/2, handle_cast/2, handle_call/3, terminate/2, code_change/3]).
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
  peername = undefined,
  compressor,
  connect_fun
}).

%%%===================================================================
%%% API
%%%===================================================================

socket_options() ->
    [binary, {active, false}, {reuseaddr, false}, {broadcast, true}].

give_socket(Host, Socket, Transport) ->
    case Transport:controlling_process(Socket, Host) of
        ok ->
            io:format("Process transferred 1~n"),
            gen_server:cast(Host, {give_socket, Socket, Transport}),
            {ok, Host};
        {error, Reason} ->
            io:format("Failed to transfer process: ~p~n", [Reason]),
            {error, Reason}
    end.

    %%ok = Transport:controlling_process(Socket, Host),
    %%io:format("Process transferred 1"),
    %%ok = gen_udp:controlling_process(Socket, Host),
    %%gen_server:cast(Host, {give_socket, Socket, Transport}).

connect(Host, IP, Port, ChannelCount, Data) ->
    gen_server:call(Host, {connect, IP, Port, ChannelCount, Data}).

send_outgoing_commands(Host, Commands, IP, Port) ->
    send_outgoing_commands(Host, Commands, IP, Port, ?NULL_PEER_ID).

send_outgoing_commands(Host, Commands, IP, Port, PeerID) ->
    gen_server:call(
        Host, {send_outgoing_commands, Commands, IP, Port, PeerID}
    ).

get_port(Host) ->
    gproc:get_value({p, l, port}, Host).

get_incoming_bandwidth(Host) ->
    gproc:get_value({p, l, incoming_bandwidth}, Host).

get_outgoing_bandwidth(Host) ->
    gproc:get_value({p, l, outgoing_bandwidth}, Host).

get_mtu(Host) ->
    gproc:get_value({p, l, mtu}, Host).

get_peer_id(Host) ->
    gproc:get_value({p, l, peer_id}, Host).

get_channel_limit(Host) ->
    gproc:get_value({p, l, channel_limit}, Host).


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
    io:format("Init echo server AssignedPort ~p~n", [AssignedPort]),
    HostID = make_ref(),
    true = gproc:reg({n, l, {enet_host, HostID}}),
    %%true = gproc:reg({p, l, {assigned_port, AssignedPort}}),
    ChannelLimit =
        case lists:keyfind(channel_limit, 1, Options) of
            {channel_limit, CLimit} -> CLimit;
            false -> ?MIN_CHANNEL_COUNT
        end,
    IncomingBandwidth =
        case lists:keyfind(incoming_bandwidth, 1, Options) of
            {incoming_bandwidth, IBandwidth} -> IBandwidth;
            false -> 0
        end,
    OutgoingBandwidth =
        case lists:keyfind(outgoing_bandwidth, 1, Options) of
            {outgoing_bandwidth, OBandwidth} -> OBandwidth;
            false -> 0
        end,
    Compressor = 
        case lists:keyfind(compression_mode, 1, Options) of
            {compression_mode, CompressionMode} -> CompressionMode;
            false -> none
        end,
    true = gproc:mreg(
        p,
        l,
        [
            {port, AssignedPort},
            {channel_limit, ChannelLimit},
            {incoming_bandwidth, IncomingBandwidth},
            {outgoing_bandwidth, OutgoingBandwidth},
            {mtu, ?HOST_DEFAULT_MTU}
        ]
    ),

    %% Store raw args and defer the actual wait() to handle_continue
    State0 = #state{transport = Transport,
                    raw_socket = RawSocket,
                    connect_fun = ConnectFun, 
                    compressor = Compressor,
                    peername = undefined,
                    socket = undefined},
      %%TODO: Evaluate restart behaviour
      %%ok = inet:setopts(Socket, [{active, true}]),

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
 

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

connected({call, From}, {connect, IP, Port, Channels, Data}, S) ->
    %%
    %% Connect to a remote peer.
    %%
    %% - Add a peer to the pool
    %% - Start the peer process
    %%
    #state{
        socket = Socket,
        connect_fun = ConnectFun
    } = S,
    Ref = make_ref(),
    LocalPort = get_port(self()),
    Reply =
        try enet_pool:add_peer(LocalPort, Ref) of
            PeerID ->
                Peer = #enet_peer{
                    handshake_flow = local,
                    peer_id = PeerID,
                    ip = IP,
                    port = Port,
                    name = Ref,
                    host = self(),
                    channels = Channels,
                    connect_fun = ConnectFun,
                    connect_packet_data = Data
                },
                start_peer(Peer)
        catch
            error:pool_full -> {error, reached_peer_limit};
            error:exists -> {error, exists}
        end,
  
    {keep_state, S, [{reply, From, Reply}]};

connected({call, From}, {send_outgoing_commands, C, IP, Port, ID}, S) ->
    %%
    %% Received outgoing commands from a peer.
    %%
    %% - Compress commands if compressor available
    %% - Wrap the commands in a protocol header
    %% - Send the packet
    %% - Return sent time
    %%
    #state{
        compressor = CompressionMode
    } = S,
    {Compressed, Commands} = 
        case CompressionMode of
            none -> 
                {0, C}; % uncompressed
            Compressor ->
                {1, compress(C, Compressor)}
        end,
    SentTime = get_time(),
    PH = #protocol_header{
        compressed = Compressed,
        peer_id = ID,
        sent_time = SentTime
    },
    Packet = [enet_protocol_encode:protocol_header(PH), Commands],
    ok = gen_udp:send(S#state.socket, IP, Port, Packet),
    {keep_state, S, [{reply, From, {sent_time, SentTime}}]};

%%%
%%% handle_cast
%%%
connected(cast, {give_socket, Socket, Transport}, S) ->
    ok = Transport:setopts(Socket, [{active, true}]),
    {ok, PeerName} = Transport:peername(Socket),
    io:format("Process transferred 2"),
    %%ok = inet:setopts(Socket, [{active, true}]),
    {keep_state, S#state{socket = Socket, transport = Transport, peername = PeerName}};

%%%
%%% handle_info
%%%
%%% Handle all DTLS/SSL messages
connected(info, {ssl, _Raw, Packet}, State = #state{transport=T, socket=S, peername=P}) ->
    io:format("Inside host sup~n"),
    io:format("~s ← ~p~n", [esockd:format(P), Packet]),
    T:async_send(S, Packet),
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

%%
%% Handle UDP
%%
connected(info, {udp, Socket, IP, Port, Packet}, StateData) ->
    %% demultiplex the incoming UDP packet
    demux_packet(Socket, IP, Port, Packet, StateData),
    {keep_state, StateData};

connected(info, {gproc, unreg, _Ref, {n, l, {enet_peer, Ref}}}, S) ->
    %%
    %% A Peer process has exited.
    %%
    %% - Remove it from the pool
    %%
    #state{
        socket = Socket
    } = S,
    LocalPort = get_port(self()),
    true = enet_pool:remove_peer(LocalPort, Ref),
    {keep_state, S};

connected(info, _Other, State) ->
    {keep_state, State};

connected(_EventType, _Msg, State) ->
    {keep_state, State}.

%%%
%%% terminate
%%%
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
terminate(Reason, _StateName, S) ->
    io:format("terminatin ~p~n",[Reason]).
    %%ok = gen_udp:close(S#state.socket).

%%terminate(Reason, _StateName, State) ->
    %% Invalid Unexpected State
%%    io:format("Invalid state on terminate/3: ~p~n~p~n", [State, Reason]),
%%    unknown.


%%%
%%% code_change
%%%

code_change(_OldVsn, _StateName, State, _Extra) ->
    {ok, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================

demux_packet(Socket, IP, Port, Packet, S) ->
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
                    {ok, Pid} = start_peer(Peer),
                    true = gproc:reg({p, l, {peer_id, PeerID}}),
                    enet_peer:recv_incoming_packet(Pid, IP, SentTime, Commands)
            catch
                error:pool_full -> {error, reached_peer_limit};
                error:exists -> {error, exists}
            end;
        PeerID ->
            case enet_pool:pick_peer(LocalPort, PeerID) of
                %% Unknown peer - drop the packet
                %% In SSL, will drop packet if socket and packet peerid
                %% don't match
                false ->
                    ok;
                Pid ->
                    enet_peer:recv_incoming_packet(Pid, IP, SentTime, Commands)
            end
    end.

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
