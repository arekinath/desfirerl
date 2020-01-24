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

-module(desfire_skey_fsm).

-compile([{parse_transform, lager_transform}]).

-behaviour(gen_statem).

-export([start_link/0]).
-export([init/1, terminate/3]).
-export([callback_mode/0]).

-export([wait_for_auth/3, authed/3, accumulate/3]).

-include("desfire_cmds.hrl").

start_link() ->
    gen_statem:start_link(?MODULE, [], []).

-record(state, {
    cipher :: atom(),
    rnda :: binary() | undefined,
    rndb :: binary() | undefined,
    iv :: binary() | undefined,
    key :: binary() | undefined,
    cmac1 :: binary() | undefined,
    cmac2 :: binary() | undefined,
    afbuf = <<>> :: binary()
}).

init([]) ->
    {ok, wait_for_auth, #state{}}.

terminate(_Why, _St, _S) -> ok.

callback_mode() -> [state_functions, state_enter].

encrypt(_, <<>>, S = #state{}) ->
    {<<>>, S};
encrypt(send, Data0, S0 = #state{cipher = Cipher, iv = IV0, key = Key}) ->
    #{iv_length := 0, block_size := BS} = crypto:cipher_info(Cipher),
    <<Plain0:BS/binary, RemPlain/binary>> = Data0,
    Plain1 = crypto:exor(Plain0, IV0),
    Enc = crypto:block_encrypt(Cipher, Key, Plain1),
    S1 = S0#state{iv = Enc},
    {RemEnc, S2} = encrypt(send, RemPlain, S1),
    {<<Enc/binary, RemEnc/binary>>, S2};
encrypt(recv, Data0, S0 = #state{cipher = Cipher, iv = IV0, key = Key}) ->
    #{iv_length := 0, block_size := BS} = crypto:cipher_info(Cipher),
    <<Plain0:BS/binary, RemPlain/binary>> = Data0,
    Enc0 = crypto:block_encrypt(Cipher, Key, Plain0),
    Enc1 = crypto:exor(Enc0, IV0),
    S1 = S0#state{iv = Plain0},
    {RemEnc, S2} = encrypt(recv, RemPlain, S1),
    {<<Enc1/binary, RemEnc/binary>>, S2}.

decrypt(_, <<>>, S = #state{}) ->
    {<<>>, S};
decrypt(send, Data0, S0 = #state{cipher = Cipher, iv = IV0, key = Key}) ->
    #{iv_length := 0, block_size := BS} = crypto:cipher_info(Cipher),
    <<Plain0:BS/binary, RemPlain/binary>> = Data0,
    Plain1 = crypto:exor(Plain0, IV0),
    Enc = crypto:block_decrypt(Cipher, Key, Plain1),
    S1 = S0#state{iv = Enc},
    {RemEnc, S2} = decrypt(send, RemPlain, S1),
    {<<Enc/binary, RemEnc/binary>>, S2};
decrypt(recv, Data0, S0 = #state{cipher = Cipher, iv = IV0, key = Key}) ->
    #{iv_length := 0, block_size := BS} = crypto:cipher_info(Cipher),
    <<Plain0:BS/binary, RemPlain/binary>> = Data0,
    Enc0 = crypto:block_decrypt(Cipher, Key, Plain0),
    Enc1 = crypto:exor(Enc0, IV0),
    S1 = S0#state{iv = Plain0},
    {RemEnc, S2} = decrypt(recv, RemPlain, S1),
    {<<Enc1/binary, RemEnc/binary>>, S2}.

wait_for_auth(enter, _, S = #state{}) ->
    {keep_state, S#state{afbuf = <<>>}};

wait_for_auth(cast, restart, #state{}) ->
    keep_state_and_data;
wait_for_auth(cast, {tx_mac, _Cmd, _Data0}, S = #state{}) ->
    {next_state, wait_for_auth, S};
wait_for_auth(cast, {rx_mac, _Cmd, _Data0}, S = #state{}) ->
    {next_state, wait_for_auth, S};
wait_for_auth({call, From}, {tx_mac, _Cmd, _Data0}, S = #state{}) ->
    gen_statem:reply(From, {error, no_auth}),
    {next_state, wait_for_auth, S};
wait_for_auth({call, From}, {rx_mac, _Cmd, _Data0}, S = #state{}) ->
    gen_statem:reply(From, {error, no_auth}),
    {next_state, wait_for_auth, S};
wait_for_auth({call, From}, {tx_encrypt, _Cmd, _Data0}, S = #state{}) ->
    gen_statem:reply(From, {error, no_auth}),
    {next_state, wait_for_auth, S};
wait_for_auth({call, From}, {rx_decrypt, _SW, _Data0, _}, S = #state{}) ->
    gen_statem:reply(From, {error, no_auth}),
    {next_state, wait_for_auth, S};

wait_for_auth({call, From}, {auth_init, Cipher, Key, ERndB}, S0 = #state{}) ->
    #{iv_length := 0, block_size := BS, key_length := KL} =
        crypto:cipher_info(Cipher),
    KL = byte_size(Key),

    IV0 = <<0:BS/unit:8>>,
    S1 = S0#state{cipher = Cipher, iv = IV0, key = Key},

    {RndB, S2} = decrypt(recv, ERndB, S1),
    RndBP = utils:rotate_left_once(RndB),

    RndA = crypto:strong_rand_bytes(BS),

    {ToSend, S3} = encrypt(send, <<RndA/binary, RndBP/binary>>, S2),

    gen_statem:reply(From, {ok, ToSend}),

    {next_state, wait_for_auth, S3#state{rnda = RndA, rndb = RndB}};

wait_for_auth({call, From}, {auth_final, ERndAP}, S0 = #state{cipher = Cipher}) ->
    #{iv_length := 0, block_size := BS, key_length := KL} =
        crypto:cipher_info(Cipher),

    {RndAP, S1} = decrypt(recv, ERndAP, S0),
    RndA = utils:rotate_right_once(RndAP),

    case S1#state.rnda of
        RndA ->
            gen_statem:reply(From, ok),

            RndB = S1#state.rndb,
            SessKey0 = case {KL, BS} of
                {16, 16} ->
                    <<First4A:4/binary, _:8/binary, Last4A:4/binary>> = RndA,
                    <<First4B:4/binary, _:8/binary, Last4B:4/binary>> = RndB,
                    <<First4A/binary, First4B/binary, Last4A/binary, Last4B/binary>>;
                {8, _} ->
                    <<First4A:4/binary, _/binary>> = RndA,
                    <<First4B:4/binary, _/binary>> = RndB,
                    <<First4A/binary, First4B/binary>>
            end,
            SessKey1 = case Cipher of
                des_ecb -> utils:des_fix_parity(SessKey0);
                des3_ecb -> utils:des_fix_parity(SessKey0);
                aes_128_ecb -> SessKey0
            end,

            IV0 = <<0:BS/unit:8>>,
            S2 = S1#state{iv = IV0, key = SessKey1},

            R = case BS of
                8 -> <<16#1B:BS/big-unit:8>>;
                _ -> <<16#87:BS/big-unit:8>>
            end,
            T = crypto:block_encrypt(Cipher, SessKey1, <<0:BS/unit:8>>),

            <<CM1V0:BS/big-unit:8>> = T,
            CM1V1 = CM1V0 bsl 1,
            CM1A = <<CM1V1:BS/big-unit:8>>,
            CM1 = case T of
                <<1:1, _/bitstring>> -> crypto:exor(CM1A, R);
                _ -> CM1A
            end,

            <<CM2V0:BS/big-unit:8>> = CM1,
            CM2V1 = CM2V0 bsl 1,
            CM2A = <<CM2V1:BS/big-unit:8>>,
            CM2 = case CM1 of
                <<1:1, _/bitstring>> -> crypto:exor(CM2A, R);
                _ -> CM2A
            end,

            S3 = S2#state{cmac1 = CM1, cmac2 = CM2},

            {next_state, authed, S3};
        _ ->
            gen_statem:reply(From, {error, bad_crypto}),
            {next_state, wait_for_auth, S1}
    end.

authed(enter, _, #state{}) ->
    keep_state_and_data;

authed(_, {auth_init, _, _, _}, S = #state{}) ->
    {next_state, wait_for_auth, S, [postpone]};
authed(cast, restart, S = #state{}) ->
    {next_state, wait_for_auth, S};

authed(Reply, {tx_mac, Cmd, Data0}, S0 = #state{}) ->
    #state{cmac1 = CM1, cmac2 = CM2, cipher = Cipher} = S0,
    #{block_size := BS} = crypto:cipher_info(Cipher),
    #desfire_cmd{ins = Ins, reset_mac = ResetMac} = Cmd,
    Data1 = <<Ins, Data0/binary>>,
    {Padding, Data2} = utils:eighty_pad(BS, Data1),
    {DataPrefix, LastBlock0} = utils:split_last_n_bytes(BS, Data2),
    LastBlock1 = case Padding of
        0 -> crypto:exor(LastBlock0, CM1);
        _ -> crypto:exor(LastBlock0, CM2)
    end,
    {_, S1} = encrypt(send, <<DataPrefix/binary, LastBlock1/binary>>, S0),
    case Reply of
        {call, From} -> gen_statem:reply(From, {ok, S1#state.iv});
        cast -> ok
    end,
    case ResetMac of
        true -> {next_state, wait_for_auth, S1};
        false -> {next_state, authed, S1}
    end;

authed(cast, {rx_mac, 16#AF, Data0}, S = #state{}) ->
    {next_state, accumulate, S#state{afbuf = Data0}};

authed(Reply, {rx_mac, SW = 16#00, Data0}, S0 = #state{afbuf = AfBuf0}) ->
    #state{cmac1 = CM1, cmac2 = CM2, cipher = Cipher} = S0,
    #{block_size := BS} = crypto:cipher_info(Cipher),
    Data1 = <<AfBuf0/binary, Data0/binary, SW>>,
    {Padding, Data2} = utils:eighty_pad(BS, Data1),
    {DataPrefix, LastBlock0} = utils:split_last_n_bytes(BS, Data2),
    LastBlock1 = case Padding of
        0 -> crypto:exor(LastBlock0, CM1);
        _ -> crypto:exor(LastBlock0, CM2)
    end,
    {_, S1} = encrypt(send, <<DataPrefix/binary, LastBlock1/binary>>, S0),
    case Reply of
        {call, From} -> gen_statem:reply(From, {ok, S1#state.iv});
        cast -> ok
    end,
    {next_state, authed, S1#state{afbuf = <<>>}};

authed(cast, {rx_mac, _Err, _}, S = #state{}) ->
    {next_state, wait_for_auth, S};

authed({call, From}, {raw_encrypt, Dirn, Data0}, S0 = #state{}) ->
    {Data1, S1} = encrypt(Dirn, Data0, S0),
    gen_statem:reply(From, {ok, Data1}),
    {next_state, authed, S1};

authed({call, From}, {raw_decrypt, Dirn, Data0}, S0 = #state{}) ->
    {Data1, S1} = decrypt(Dirn, Data0, S0),
    gen_statem:reply(From, {ok, Data1}),
    {next_state, authed, S1};

authed({call, From}, {tx_encrypt, Cmd, Data0}, S0 = #state{cipher = Cipher}) ->
    #{block_size := BS} = crypto:cipher_info(Cipher),
    #desfire_cmd{ins = Ins, header_len = HdrLen} = Cmd,
    CRC = utils:crc32(<<Ins:8, Data0/binary>>),
    <<Hdrs:HdrLen/binary, Data1/binary>> = Data0,
    Data2 = <<Data1/binary, CRC/binary>>,
    {_Padding, Data3} = utils:zero_pad(BS, Data2),
    {Data4, S1} = encrypt(send, Data3, S0),
    gen_statem:reply(From, {ok, <<Hdrs/binary, Data4/binary>>}),
    {next_state, authed, S1};

authed(cast, {rx_decrypt, 16#AF, Data0, _ExpectLen}, S = #state{}) ->
    {next_state, accumulate, S#state{afbuf = Data0}};
authed(Reply, {rx_decrypt, SW = 16#00, Data0, ExpectLen}, S0 = #state{afbuf = AfBuf0}) ->
    Data1 = <<AfBuf0/binary, Data0/binary>>,
    {Data2, S1} = decrypt(recv, Data1, S0),
    {Data3, TheirCRC} = case ExpectLen of
        none ->
            {RealLenWithCRC, 1} = lists:last(binary:matches(Data2,
                [<<16#80>>])),
            RealLen = RealLenWithCRC - 4,
            Padding = byte_size(Data2) - RealLenWithCRC - 1,
            <<RealData:RealLen/binary, CRCBin:4/binary,
              16#80, 0:Padding/unit:8>> = Data2,
            {RealData, CRCBin};
        _ ->
            Padding = byte_size(Data2) - ExpectLen - 4,
            <<RealData:ExpectLen/binary, CRCBin:4/binary,
              0:Padding/unit:8>> = Data2,
            {RealData, CRCBin}
    end,
    OurCRC = utils:crc32(<<Data3/binary, SW>>),
    OurCRC = TheirCRC,
    case Reply of
        {call, From} -> gen_statem:reply(From, {ok, Data3});
        cast -> ok
    end,
    {next_state, authed, S1#state{afbuf = <<>>}}.

accumulate(enter, _, #state{}) ->
    keep_state_and_data;
accumulate(cast, {rx_decrypt, 16#AF, Data0, _}, S = #state{}) ->
    #state{afbuf = AfBuf0} = S,
    AfBuf1 = <<AfBuf0/binary, Data0/binary>>,
    {next_state, accumulate, S#state{afbuf = AfBuf1}};
accumulate(cast, {rx_mac, 16#AF, Data0}, S = #state{}) ->
    #state{afbuf = AfBuf0} = S,
    AfBuf1 = <<AfBuf0/binary, Data0/binary>>,
    {next_state, accumulate, S#state{afbuf = AfBuf1}};
accumulate(_, _, S = #state{}) ->
    {next_state, authed, S, [postpone]}.
