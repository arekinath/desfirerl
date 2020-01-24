%%
%% desfire host implementation
%%
%% Copyright 2020 Alex Wilson <alex@uq.edu.au>, The University of Queensland
%%
%% Redistribution and use in source and binary forms, with or without
%% modification, are permitted provided that the following conditions
%% are met:
%% 1. Redistributions of source code must retain the above copyright
%%    notice, this list of conditions and the following disclaimer.
%% 2. Redistributions in binary form must reproduce the above copyright
%%    notice, this list of conditions and the following disclaimer in the
%%    documentation and/or other materials provided with the distribution.
%%
%% THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
%% IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
%% OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
%% IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
%% INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
%% NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
%% DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
%% THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
%% (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
%% THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

-module(desfire_proto).

-compile([{parse_transform, lager_transform}]).

-include_lib("pcsc/include/iso7816.hrl").

-behaviour(gen_statem).

-export([start_link/2]).
-export([init/1, terminate/3]).
-export([callback_mode/0]).

-export([handle_event/4]).

-include("desfire_cmds.hrl").

start_link(Reader, Writer) ->
    gen_statem:start_link(?MODULE, [Reader, Writer], []).

-record(state, {
    rdr :: pid(),
    wr :: pid(),
    skey :: pid(),
    aid :: binary() | undefined,
    kid :: integer() | undefined,
    finfo = #{} :: map()
}).

init([Reader, Writer]) ->
    {ok, SKey} = desfire_skey_fsm:start_link(),
    {ok, start, #state{rdr = Reader, wr = Writer, skey = SKey}}.

terminate(_Why, _St, _S) -> ok.

callback_mode() -> [handle_event_function, state_enter].

handle_event(enter, _OldState, start, S = #state{skey = SKey}) ->
    gen_statem:cast(SKey, restart),
    {keep_state, S#state{finfo = #{}}};
handle_event(enter, _OldState, app_selected, S = #state{skey = SKey}) ->
    gen_statem:cast(SKey, restart),
    {keep_state, S#state{finfo = #{}}};
handle_event(enter, _OldState, _State, #state{}) ->
    keep_state_and_data;

handle_event({call, From}, {select_app, Aid}, _State, S0 = #state{}) ->
    case handle_command(?CMD_SELECT_APP, Aid, S0) of
        {ok, _, S1} ->
            gen_statem:reply(From, ok),
            {next_state, app_selected, S1#state{aid = Aid}};
        {error, E, _, S1} ->
            gen_statem:reply(From, {error, E}),
            {next_state, start, S1}
    end;

handle_event({call, From}, format_card, authed, S0 = #state{aid = ?PICC_AID}) ->
    case handle_command(?CMD_FORMAT_PICC, <<>>, S0) of
        {ok, _, S1} ->
            gen_statem:reply(From, ok),
            {next_state, authed, S1};
        {error, E, _, S1} ->
            gen_statem:reply(From, {error, E}),
            {next_state, start, S1}
    end;

handle_event({call, From}, {create_app, Aid, Args}, State, S0 = #state{}) ->
    KeySettings = desfire_data:encode_app_key_settings(Args),
    CmdData = <<Aid/binary, KeySettings/binary>>,
    case handle_command(?CMD_CREATE_APP, CmdData, S0) of
        {ok, _, S1} ->
            gen_statem:reply(From, ok),
            {next_state, State, S1};
        {error, E, _, S1} ->
            gen_statem:reply(From, {error, E}),
            {next_state, start, S1}
    end;

handle_event({call, From}, get_version, State, S0 = #state{}) ->
    Cmd = ?CMD_GET_VERSION,
    case handle_command(Cmd, <<>>, S0) of
        {error, additional, Data0, S1} ->
            case continue_reply(Cmd, S1) of
                {ok, Data1, S2} ->
                    Data = <<Data0/binary, Data1/binary>>,
                    <<HWInfo:7/binary, SWInfo:7/binary,
                      UID:7/binary, Batch:40/little, Week, Year>> = Data,
                    Ret = #{
                        uid => UID,
                        batch => Batch,
                        produced => {Year, Week},
                        hwinfo => desfire_data:decode_version_info(HWInfo),
                        swinfo => desfire_data:decode_version_info(SWInfo)
                    },
                    gen_statem:reply(From, {ok, Ret}),
                    {next_state, State, S2};
                {error, E, S2} ->
                    gen_statem:reply(From, {error, E}),
                    {next_state, start, S2}
            end;
        {error, E2, _, S1} ->
            gen_statem:reply(From, {error, E2}),
            {next_state, start, S1}
    end;

handle_event({call, From}, get_key_settings, start, S0 = #state{}) ->
    gen_statem:reply(From, {error, no_app_selected}),
    {next_state, start, S0};

handle_event({call, From}, get_key_settings, State, S0 = #state{aid = Aid}) ->
    case handle_command(?CMD_GET_KEY_SETTINGS, <<>>, S0) of
        {ok, Data, S1} ->
            Ret = case Aid of
                ?PICC_AID -> desfire_data:decode_picc_key_settings(Data);
                _ -> desfire_data:decode_app_key_settings(Data)
            end,
            gen_statem:reply(From, {ok, Ret}),
            {next_state, State, S1};
        {error, E, _, S1} ->
            gen_statem:reply(From, {error, E}),
            {next_state, start, S1}
    end;

handle_event({call, From}, {set_file_security, _, _}, start, S0 = #state{}) ->
    gen_statem:reply(From, {error, no_app_selected}),
    {next_state, start, S0};

handle_event({call, _}, {set_file_security, FileNo, Mode}, State, S0 = #state{}) ->
    #state{finfo = FInfo0} = S0,
    FInfo1 = FInfo0#{FileNo => Mode},
    S1 = S0#state{finfo = FInfo1},
    {next_state, State, S1};

handle_event({call, From}, {get_file_info, _}, start, S0 = #state{}) ->
    gen_statem:reply(From, {error, no_app_selected}),
    {next_state, start, S0};

handle_event({call, From}, {get_file_info, FileNo}, State, S0 = #state{}) ->
    case handle_command(?CMD_GET_FILE_INFO, <<FileNo>>, S0) of
        {ok, Data, S1} ->
            Ret = desfire_data:decode_file_info(Data),
            #{security := Mode} = Ret,
            #state{finfo = FInfo0} = S0,
            FInfo1 = FInfo0#{FileNo => Mode},
            S2 = S1#state{finfo = FInfo1},
            gen_statem:reply(From, {ok, Ret}),
            {next_state, State, S2};
        {error, E, _, S1} ->
            gen_statem:reply(From, {error, E}),
            {next_state, start, S1}
    end;

handle_event({call, From}, {write_std_file, FileNo, Offset, Data}, State, S0 = #state{}) ->
    #state{finfo = FInfo0} = S0,
    case FInfo0 of
        #{FileNo := Mode} ->
            Cmd0 = ?CMD_WRITE_STD_FILE,
            Cmd1 = case Mode of
                encrypted -> Cmd0;
                mac -> Cmd0#desfire_cmd{tx = mac};
                plain -> Cmd0#desfire_cmd{tx = mac, add_mac = false}
            end,
            Length = byte_size(Data),
            CmdData = <<FileNo, Offset:24/little, Length:24/little, Data/binary>>,
            case handle_command(Cmd1, CmdData, S0) of
                {ok, _, S1} ->
                    gen_statem:reply(From, ok),
                    {next_state, State, S1};
                {error, E, _, S1} ->
                    gen_statem:reply(From, {error, E}),
                    {next_state, start, S1}
            end;
        _ ->
            gen_statem:reply(From, {error, unknown_file_mode}),
            {next_state, State, S0}
    end;

handle_event({call, From}, {read_std_file, _, _, _}, start, S0 = #state{}) ->
    gen_statem:reply(From, {error, no_app_selected}),
    {next_state, start, S0};

handle_event({call, From}, {read_std_file, FileNo, Offset, Length}, State, S0 = #state{}) ->
    #state{finfo = FInfo0} = S0,
    case FInfo0 of
        #{FileNo := Mode} ->
            Cmd0 = ?CMD_READ_STD_FILE,
            Cmd1 = case Mode of
                encrypted -> Cmd0;
                mac -> Cmd0#desfire_cmd{rx = mac};
                plain -> Cmd0#desfire_cmd{rx = mac}
            end,
            Length1 = case Length of
                all -> 0;
                _ -> Length
            end,
            Cmd2 = case Length of
                all -> Cmd1#desfire_cmd{expect_len = none};
                _ -> Cmd1#desfire_cmd{expect_len = Length}
            end,
            CmdData = <<FileNo, Offset:24/little, Length1:24/little>>,
            case handle_command(Cmd2, CmdData, S0) of
                {ok, Data, S1} ->
                    gen_statem:reply(From, {ok, Data}),
                    {next_state, State, S1};
                {error, additional, Data0, S1} ->
                    case continue_reply(Cmd2, S1) of
                        {ok, Data1, S2} ->
                            Ret = case Cmd2#desfire_cmd.rx of
                                encrypt -> Data1;
                                _ -> <<Data0/binary, Data1/binary>>
                            end,
                            gen_statem:reply(From, {ok, Ret}),
                            {next_state, State, S2};
                        {error, E2, S2} ->
                            gen_statem:reply(From, {error, E2}),
                            {next_state, start, S2}
                    end;
                {error, E, _, S1} ->
                    gen_statem:reply(From, {error, E}),
                    {next_state, start, S1}
            end;
        _ ->
            gen_statem:reply(From, {error, unknown_file_mode}),
            {next_state, State, S0}
    end;

handle_event({call, From}, {create_std_file, FileNo, Args}, State, S0 = #state{}) ->
    #{security := Mode, access := Access, size := Size} = Args,
    ModeNum = desfire_data:comm_settings_from_atom(Mode),
    AccessBin = desfire_data:encode_access(Access),
    CmdData = <<FileNo, ModeNum, AccessBin/binary, Size:24/little>>,
    case handle_command(?CMD_CREATE_STD_FILE, CmdData, S0) of
        {ok, _, S1} ->
            #state{finfo = FInfo0} = S0,
            FInfo1 = FInfo0#{FileNo => Mode},
            S2 = S1#state{finfo = FInfo1},
            gen_statem:reply(From, ok),
            {next_state, State, S2};
        {error, E, _, S1} ->
            gen_statem:reply(From, {error, E}),
            {next_state, start, S1}
    end;

handle_event({call, From}, {change_file_settings, FileNo, Args}, State, S0 = #state{}) ->
    #{security := Mode, access := Access} = Args,
    ModeNum = desfire_data:comm_settings_from_atom(Mode),
    AccessBin = desfire_data:encode_access(Access),
    CmdData = <<FileNo, ModeNum, AccessBin/binary>>,
    case handle_command(?CMD_CHANGE_FILE_SETTINGS, CmdData, S0) of
        {ok, _, S1} ->
            #state{finfo = FInfo0} = S0,
            FInfo1 = FInfo0#{FileNo => Mode},
            S2 = S1#state{finfo = FInfo1},
            gen_statem:reply(From, ok),
            {next_state, State, S2};
        {error, E, _, S1} ->
            gen_statem:reply(From, {error, E}),
            {next_state, start, S1}
    end;

handle_event({call, From}, {change_key, _, _, _}, start, S0 = #state{}) ->
    gen_statem:reply(From, {error, no_app_selected}),
    {next_state, start, S0};
handle_event({call, From}, {change_key, _, _, _}, app_selected, S0 = #state{}) ->
    gen_statem:reply(From, {error, no_auth}),
    {next_state, start, S0};
handle_event({call, From}, {change_key, KeyNo, Args}, _, S0 = #state{}) ->
    #{old_key := OldKey, new_key := NewKey, cipher := Cipher,
      version := Vsn} = Args,

    #{key_length := KL, block_size := BS} = crypto:cipher_info(Cipher),
    KL = byte_size(OldKey),
    KL = byte_size(NewKey),

    CG0 = NewKey,
    CG1 = case S0 of
        #state{kid = KeyNo} -> CG0;
        _ -> crypto:exor(CG0, OldKey)
    end,
    CG2 = case Cipher of
        aes_128_ecb -> <<CG1/binary, Vsn>>;
        _ -> CG1
    end,
    CRC = utils:crc32(<<?INS_CHANGE_KEY, KeyNo, CG2/binary>>),
    CG3 = <<CG2/binary, CRC/binary>>,
    CG4 = case S0 of
        #state{kid = KeyNo} -> CG3;
        _ ->
            CRCNew = utils:crc32(NewKey),
            <<CG3/binary, CRCNew/binary>>
    end,
    {_, CG5} = utils:zero_pad(BS, CG4),
    #state{skey = SKey} = S0,
    {ok, CG6} = gen_statem:call(SKey, {raw_encrypt, send, CG5}),

    Cmd = ?CMD_CHANGE_KEY,
    CmdData = <<KeyNo, CG6/binary>>,

    case handle_command(Cmd, CmdData, S0) of
        {ok, _, S1} ->
            gen_statem:cast(SKey, restart),
            gen_statem:reply(From, ok),
            {next_state, app_selected, S1};
        {error, Err, _, S1} ->
            en_statem:reply(From, {error, Err}),
            {next_state, start, S1}
    end;

handle_event({call, From}, {authenticate, _, _, _}, start, S0 = #state{}) ->
    gen_statem:reply(From, {error, no_app_selected}),
    {next_state, start, S0};

handle_event({call, From}, {authenticate, KeyNo, Cipher, Key}, _, S0 = #state{}) ->
    #{key_length := KL} = crypto:cipher_info(Cipher),
    KL = byte_size(Key),
    #state{skey = SKey} = S0,
    Cmd = case Cipher of
        des_ecb -> ?CMD_AUTHENTICATE_ISO;
        des3_ecb -> ?CMD_AUTHENTICATE_ISO;
        aes_128_ecb -> ?CMD_AUTHENTICATE_AES
    end,
    case handle_command(Cmd, <<KeyNo>>, S0) of
        {error, additional, ERndB, S1} ->
            {ok, ToSend} = gen_statem:call(SKey, {auth_init, Cipher, Key,
                ERndB}),
            case handle_command(?CMD_CONTINUE_AUTH, ToSend, S1) of
                {ok, ERndAP, S2} ->
                    case gen_statem:call(SKey, {auth_final, ERndAP}) of
                        ok ->
                            gen_statem:reply(From, ok),
                            {next_state, authed, S2#state{kid = KeyNo}};
                        Err ->
                            gen_statem:reply(From, Err),
                            {next_state, start, S2}
                    end;
                {error, Err2, _, S2} ->
                    gen_statem:reply(From, {error, Err2}),
                    {next_state, start, S2}
            end;
        {error, Err3, _, S1} ->
            gen_statem:reply(From, {error, Err3}),
            {next_state, start, S1}
    end.

continue_reply(Cmd0, S0 = #state{}) ->
    #desfire_cmd{rx = RxMode} = Cmd0,
    Cmd1 = Cmd0#desfire_cmd{ins = ?INS_CONTINUE, tx = none},
    case handle_command(Cmd1, <<>>, S0) of
        {ok, Data, S1} ->
            {ok, Data, S1};
        {error, additional, Data, S1} ->
            case continue_reply(Cmd0, S1) of
                {ok, Data1, S2} when (RxMode =:= encrypt) ->
                    {ok, Data1, S2};
                {ok, Data1, S2} ->
                    {ok, <<Data/binary, Data1/binary>>, S2};
                Else -> Else
            end;
        {error, E, _, S1} -> {error, E, S1}
    end.

handle_command(Cmd = #desfire_cmd{}, Data0, S0 = #state{}) ->
    #desfire_cmd{ins = Ins, add_mac = AddMac, tx = TxMode, rx = RxMode} = Cmd,
    #state{skey = SKey} = S0,
    Data1 = case {TxMode, AddMac} of
        {none, _} ->
            Data0;
        {mac, false} ->
            gen_statem:cast(SKey, {tx_mac, Cmd, Data0}),
            Data0;
        {mac, true} ->
            {ok, Mac} = gen_statem:call(SKey, {tx_mac, Cmd, Data0}),
            <<ToAdd:8/binary, _/binary>> = Mac,
            <<Data0/binary, ToAdd/binary>>;
        {encrypt, _} ->
            {ok, EncData} = gen_statem:call(SKey, {tx_encrypt, Cmd, Data0}),
            EncData
    end,
    #state{rdr = Rdr, wr = Wr} = S0,
    ApduData = case Data1 of
        <<>> -> none;
        none -> none;
        _ -> Data1
    end,
    Le = case Data0 of
        <<>> -> 0;
        none -> none;
        _ -> 0
    end,
    Wr ! {apdu, self(), #apdu_cmd{cla = 16#90, ins = Ins, p1 = 0, p2 = 0,
        data = ApduData, le = Le}},
    receive
        {apdu, Rdr, #apdu_reply{sw = {desfire, SW2}, data = ReplyDataMaybe}} ->
            ok
    end,
    ReplyData0 = case ReplyDataMaybe of
        none -> <<>>;
        _ -> ReplyDataMaybe
    end,
    ReplyData1 = case RxMode of
        none ->
            ReplyData0;
        mac when (byte_size(ReplyData0) >= 8) and (SW2 == 16#00) ->
            {JustData, TheirMac} = utils:split_last_n_bytes(8, ReplyData0),
            R = gen_statem:call(SKey, {rx_mac, SW2, JustData}),
            case R of
                {error, no_auth} ->
                    ReplyData0;
                {ok, OurMac} ->
                    <<TheirMac:8/binary, _/binary>> = OurMac,
                    JustData
            end;
        mac ->
            gen_statem:cast(SKey, {rx_mac, SW2, ReplyData0}),
            ReplyData0;
        encrypt when (SW2 == 16#00) ->
            #desfire_cmd{expect_len = ExpectLen} = Cmd,
            {ok, DecData} = gen_statem:call(SKey,
                {rx_decrypt, SW2, ReplyData0, ExpectLen}),
            DecData;
        encrypt ->
            gen_statem:cast(SKey, {rx_decrypt, SW2, ReplyData0, none}),
            ReplyData0
    end,
    case SW2 of
        16#00 -> {ok, ReplyData1, S0};
        _ ->
            Err = desfire_data:error_to_atom(SW2),
            {error, Err, ReplyData1, S0}
    end.
