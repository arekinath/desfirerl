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

-module(utils).

-export([to_hex/1, from_hex/1]).
-export([last_n_bytes/2, split_last_n_bytes/2]).
-export([zero_pad/2, eighty_pad/2]).
-export([crc16/1, crc32/1]).
-export([rotate_left_once/1, rotate_right_once/1]).
-export([des_add_parity/1, des_fix_parity/1]).
-export([slice/2]).

slice(Len, Bin) ->
    case Bin of
        <<>> -> [];
        <<Slice:Len/binary, Rest/binary>> ->
            [Slice | slice(Len, Rest)];
        _ -> [Bin]
    end.

rotate_left_once(<<First, Rest/binary>>) ->
    <<Rest/binary, First>>.
rotate_right_once(Bin) ->
    Len1 = byte_size(Bin) - 1,
    <<Rest:Len1/binary, Last>> = Bin,
    <<Last, Rest/binary>>.

des_add_parity(B) ->
    << <<N:7,(odd_parity(N)):1>> || <<N:7>> <= B >>.
des_fix_parity(B) ->
    << <<N:7,(odd_parity(N)):1>> || <<N:7,_:1>> <= B >>.
odd_parity(N) ->
    Set = length([ 1 || <<1:1>> <= <<N>> ]),
    if (Set rem 2 == 1) -> 0; true -> 1 end.

zero_pad(BS, Bin) ->
    Len = byte_size(Bin),
    Rem = Len rem BS,
    Padding = case Rem of
        0 -> 0;
        _ -> BS - Rem
    end,
    case Padding of
        0 -> {0, Bin};
        _ -> {Padding, <<Bin/binary, 0:Padding/unit:8>>}
    end.

eighty_pad(BS, Bin) ->
    Len = byte_size(Bin),
    Rem = Len rem BS,
    Padding = case Rem of
        0 -> 0;
        _ -> BS - Rem
    end,
    Padding1 = Padding - 1,
    case Padding of
        0 -> {0, Bin};
        _ -> {Padding, <<Bin/binary, 16#80, 0:Padding1/unit:8>>}
    end.

last_n_bytes(Len, Bin) ->
    RemLen = byte_size(Bin) - Len,
    <<_:RemLen/binary, V:Len/binary>> = Bin,
    V.

split_last_n_bytes(Len, Bin) ->
    RemLen = byte_size(Bin) - Len,
    <<Rem:RemLen/binary, V:Len/binary>> = Bin,
    {Rem, V}.

to_hex(Bin) -> to_hex(<<>>, Bin).
to_hex(SoFar, <<>>) -> SoFar;
to_hex(SoFar, <<V:4, Rest/bitstring>>) ->
    Digit = if
        (V < 10) -> $0 + V;
        true -> $a + (V - 10)
    end,
    to_hex(<<SoFar/binary, Digit>>, Rest).

from_hex(Bin) -> parse_hex_digit(<<>>, Bin).

parse_hex_digit(Bin, <<>>) -> Bin;
parse_hex_digit(Bin, <<Digit:8, Rest/binary>>) when (Digit >= $0) and (Digit =< $9) ->
    V = Digit - $0,
    parse_hex_digit(<<Bin/bitstring, V:4>>, Rest);
parse_hex_digit(Bin, <<Digit:8, Rest/binary>>) when (Digit >= $a) and (Digit =< $f) ->
    V = 10 + (Digit - $a),
    parse_hex_digit(<<Bin/bitstring, V:4>>, Rest);
parse_hex_digit(Bin, <<Digit:8, Rest/binary>>) when (Digit >= $A) and (Digit =< $F) ->
    V = 10 + (Digit - $A),
    parse_hex_digit(<<Bin/bitstring, V:4>>, Rest);
parse_hex_digit(Bin, <<Space:8, Rest/binary>>) when (Space == $\n) or (Space == $\t) or (Space == 32) ->
    parse_hex_digit(Bin, Rest).

crc32(Bin) ->
    CRC = erlang:crc32(Bin),
    crypto:exor(<<16#ffffffff:32>>, <<CRC:32/little>>).

crc16(Bin) -> <<(crc16(0, Bin)):16/little>>.

crc16(V, <<>>) -> V;
crc16(V, <<Next, Rest/binary>>) ->
    Table = {16#0000, 16#C0C1, 16#C181, 16#0140, 16#C301, 16#03C0, 16#0280, 16#C241,
        16#C601, 16#06C0, 16#0780, 16#C741, 16#0500, 16#C5C1, 16#C481, 16#0440,
        16#CC01, 16#0CC0, 16#0D80, 16#CD41, 16#0F00, 16#CFC1, 16#CE81, 16#0E40,
        16#0A00, 16#CAC1, 16#CB81, 16#0B40, 16#C901, 16#09C0, 16#0880, 16#C841,
        16#D801, 16#18C0, 16#1980, 16#D941, 16#1B00, 16#DBC1, 16#DA81, 16#1A40,
        16#1E00, 16#DEC1, 16#DF81, 16#1F40, 16#DD01, 16#1DC0, 16#1C80, 16#DC41,
        16#1400, 16#D4C1, 16#D581, 16#1540, 16#D701, 16#17C0, 16#1680, 16#D641,
        16#D201, 16#12C0, 16#1380, 16#D341, 16#1100, 16#D1C1, 16#D081, 16#1040,
        16#F001, 16#30C0, 16#3180, 16#F141, 16#3300, 16#F3C1, 16#F281, 16#3240,
        16#3600, 16#F6C1, 16#F781, 16#3740, 16#F501, 16#35C0, 16#3480, 16#F441,
        16#3C00, 16#FCC1, 16#FD81, 16#3D40, 16#FF01, 16#3FC0, 16#3E80, 16#FE41,
        16#FA01, 16#3AC0, 16#3B80, 16#FB41, 16#3900, 16#F9C1, 16#F881, 16#3840,
        16#2800, 16#E8C1, 16#E981, 16#2940, 16#EB01, 16#2BC0, 16#2A80, 16#EA41,
        16#EE01, 16#2EC0, 16#2F80, 16#EF41, 16#2D00, 16#EDC1, 16#EC81, 16#2C40,
        16#E401, 16#24C0, 16#2580, 16#E541, 16#2700, 16#E7C1, 16#E681, 16#2640,
        16#2200, 16#E2C1, 16#E381, 16#2340, 16#E101, 16#21C0, 16#2080, 16#E041,
        16#A001, 16#60C0, 16#6180, 16#A141, 16#6300, 16#A3C1, 16#A281, 16#6240,
        16#6600, 16#A6C1, 16#A781, 16#6740, 16#A501, 16#65C0, 16#6480, 16#A441,
        16#6C00, 16#ACC1, 16#AD81, 16#6D40, 16#AF01, 16#6FC0, 16#6E80, 16#AE41,
        16#AA01, 16#6AC0, 16#6B80, 16#AB41, 16#6900, 16#A9C1, 16#A881, 16#6840,
        16#7800, 16#B8C1, 16#B981, 16#7940, 16#BB01, 16#7BC0, 16#7A80, 16#BA41,
        16#BE01, 16#7EC0, 16#7F80, 16#BF41, 16#7D00, 16#BDC1, 16#BC81, 16#7C40,
        16#B401, 16#74C0, 16#7580, 16#B541, 16#7700, 16#B7C1, 16#B681, 16#7640,
        16#7200, 16#B2C1, 16#B381, 16#7340, 16#B101, 16#71C0, 16#7080, 16#B041,
        16#5000, 16#90C1, 16#9181, 16#5140, 16#9301, 16#53C0, 16#5280, 16#9241,
        16#9601, 16#56C0, 16#5780, 16#9741, 16#5500, 16#95C1, 16#9481, 16#5440,
        16#9C01, 16#5CC0, 16#5D80, 16#9D41, 16#5F00, 16#9FC1, 16#9E81, 16#5E40,
        16#5A00, 16#9AC1, 16#9B81, 16#5B40, 16#9901, 16#59C0, 16#5880, 16#9841,
        16#8801, 16#48C0, 16#4980, 16#8941, 16#4B00, 16#8BC1, 16#8A81, 16#4A40,
        16#4E00, 16#8EC1, 16#8F81, 16#4F40, 16#8D01, 16#4DC0, 16#4C80, 16#8C41,
        16#4400, 16#84C1, 16#8581, 16#4540, 16#8701, 16#47C0, 16#4680, 16#8641,
        16#8201, 16#42C0, 16#4380, 16#8341, 16#4100, 16#81C1, 16#8081, 16#4040},
    Idx = (V bxor Next) band 16#ff,
    V2 = (V bsr 8) bxor (element(Idx, Table)),
    crc16(V2, Rest).
