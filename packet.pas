//this unit is there to forge and send UDP packets thru windows rack sockets.
//this way we dont need to worry about binding and reusing a used port

unit packet;

interface

uses windows,ipheader,wsck,sysutils;

//const IP_HDRINCL      = 2; //defined in wsck.pas

type TPacketBuffer=array [0..2048-1] of byte;

function SendIt(FromIP      : String;
  FromPort   : Word;
  ToIP        : String;
  ToPort     : Word;
  msg:string):integer;

implementation

function checksum2(var buf; length:integer):word;
var
  //p: pointer;
  p:pword;
  sum: longint;
  i: integer;
begin
  p:=@buf;
  sum:=0;
  for i:=1 to length div 2 do
  begin
    //sum:=sum+word(p^);
    //p:=pointer(longint(p)+2);
    Sum := Sum + htons(p^);
    inc(p);
  end;
	// if Length is OddNumber, Add Last Data
  //if length mod 1<>0 then sum:=sum+byte(p^);
	if (length div 2) * 2 <> length then
		Sum := Sum + (htons(p^) and $FF00);
	// Recalculate Sum
  while (Sum shr 16) > 0 do
		Sum := (Sum and $FFFF) + (Sum shr 16);
	Sum := not Sum;
  result:=htons(sum);
end;

procedure BuildUDPHeaders(
  FromIP      : String;
  iFromPort   : Word;
  ToIP        : String;
  iToPort     : Word;
  StrMessage  : String;
  Var Buf         : TPacketBuffer;
  Var iTotalSize  : Word
);
Var
  dwFromIP    : LongWord;
  dwToIP      : LongWord;

  iIPVersion  : Word;
  iIPSize     : Word;
  ipHdr       : TIP_Header;
  udpHdr      : TUDP_Header;

  iUdpSize    : Word;
  iUdpChecksumSize : Word;
  cksum       : Word;

  Ptr         : ^Byte;

  procedure IncPtr(Value : Integer);
  begin
    ptr := pointer(integer(ptr) + Value);
  end;

begin
   // Convert ip address'ss

   dwFromIP    := inet_Addr(PansiChar(FromIP));
   dwToIP      := inet_Addr(PansiChar(ToIP));

    // Initalize the IP header
    //
    iTotalSize := 20 + 8 + length(strMessage);

    iIPVersion := 4;
    iIPSize := sizeof(ipHdr) div sizeof(LongWord);
    //
    // IP version goes in the high order 4 bits of ip_verlen. The
    // IP header length (in 32-bit words) goes in the lower 4 bits.
    //
    ipHdr.ip_verlen := $45 ;//(iIPVersion shl 4) or iIPSize;
    ipHdr.ip_tos := 0;                         // IP type of service
    ipHdr.ip_totallength := htons(iTotalSize); // Total packet len
    ipHdr.ip_id := 0;                 // Unique identifier: set to 0
    ipHdr.ip_offset := 0;             // Fragment offset field
    ipHdr.ip_ttl := 128;              // Time to live
    ipHdr.ip_protocol := $11;         // Protocol(UDP)
    ipHdr.ip_checksum := 0 ;          // IP checksum
    ipHdr.ip_srcaddr := dwFromIP;     // Source address
    ipHdr.ip_destaddr := dwToIP;      // Destination address
    //
    // Initalize the UDP header
    //
    iUdpSize := 8 + length(strMessage);

    udpHdr.src_portno := htons( iFromPort) ;
    udpHdr.dst_portno := htons(iToPort) ;
    udpHdr.udp_length := htons(iUdpSize) ;
    udpHdr.udp_checksum := 0 ;
    //
    // Build the UDP pseudo-header for calculating the UDP checksum.
    // The pseudo-header consists of the 32-bit source IP address,
    // the 32-bit destination IP address, a zero byte, the 8-bit
    // IP protocol field, the 16-bit UDP length, and the UDP
    // header itself along with its data (padded with a 0 if
    // the data is odd length).
    //
    iUdpChecksumSize := 0;

    ptr := @buf[0];
    FillChar(Buf, SizeOf(Buf), 0);
    //ip header
    Move(ipHdr.ip_srcaddr, ptr^, SizeOf(ipHdr.ip_srcaddr));
    IncPtr(SizeOf(ipHdr.ip_srcaddr));
    iUdpChecksumSize := iUdpChecksumSize + sizeof(ipHdr.ip_srcaddr);
    //
    Move(ipHdr.ip_destaddr, ptr^, SizeOf(ipHdr.ip_destaddr));
    IncPtr(SizeOf(ipHdr.ip_destaddr));
    iUdpChecksumSize := iUdpChecksumSize + sizeof(ipHdr.ip_destaddr);
    // ?
    IncPtr(1);
    Inc(iUdpChecksumSize);
    //
    Move(ipHdr.ip_protocol, ptr^, sizeof(ipHdr.ip_protocol));
    IncPtr(sizeof(ipHdr.ip_protocol));
    iUdpChecksumSize := iUdpChecksumSize + sizeof(ipHdr.ip_protocol);
    //udp header
    Move(udpHdr.udp_length, ptr^, sizeof(udpHdr.udp_length));
    IncPtr(sizeof(udpHdr.udp_length));
    iUdpChecksumSize := iUdpChecksumSize + sizeof(udpHdr.udp_length);
    //
    move(udpHdr, ptr^, 8);
    IncPtr(8);
    iUdpChecksumSize := iUdpCheckSumSize + 8;
    //data
    Move(StrMessage[1], ptr^, Length(strMessage));
    IncPtr(Length(StrMessage));
    iUdpChecksumSize := iUdpChecksumSize + length(strMessage);
    //
    cksum := checksum2(buf, iUdpChecksumSize);
    udpHdr.udp_checksum := cksum;

    //
    // Now assemble the IP and UDP headers along with the data
    //  so we can send it
    //
    FillChar(Buf, SizeOf(Buf), 0);
    Ptr := @Buf[0];

    Move(ipHdr, ptr^, 20);    incptr(20);  //IncPtr(SizeOf(ipHdr));
    Move(udpHdr, ptr^, 8);  incptr(8);   //IncPtr(SizeOf(udpHdr));
    Move(StrMessage[1], ptr^, length(StrMessage));

end;

{
https://docs.microsoft.com/en-us/windows/desktop/winsock/tcp-ip-raw-sockets-2
-TCP data cannot be sent over raw sockets.
-UDP datagrams with an invalid source address cannot be sent over raw sockets.
The IP source address for any outgoing UDP datagram must exist on a network interface or the datagram is dropped.
This change was made to limit the ability of malicious code to create distributed denial-of-service attacks
and limits the ability to send spoofed packets (TCP/IP packets with a forged source IP address).
-A call to the bind function with a raw socket for the IPPROTO_TCP protocol is not allowed.
}
function SendIt(FromIP      : String;
  FromPort   : Word;
  ToIP        : String;
  ToPort     : Word;
  msg:string):integer;
Var
  sh          : TSocket;
  bOpt        : Integer;
  ret         : Integer;
  Buf         : TPacketBuffer;
  sa,Remote      : TSockAddr;
  iTotalSize  : Word;
  wsdata      : TWSAdata;

begin
result:=0;
  // Startup Winsock 2
  ret := WSAStartup($0002, wsdata);
  if ret<>0 then
  begin
    raise exception.create('WSA Startup failed.');
    exit;
  end;


  try
    // Create socket
    sh := Socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (sh = INVALID_SOCKET) then begin
      raise exception.create('Socket() failed: '+IntToStr(WSAGetLastError));
      exit;
    end;
    //Memo1.lines.add('Socket Handle = '+IntToStr(sh));

    {
    sa.sin_family := AF_INET;
    sa.sin_port := htons(138);
    //sa.sin_addr.s_addr := ip^;
    sa.sin_addr.S_addr :=inet_Addr(PansiChar(ansistring(FromIP )));

    // ***************** BIND *******************
    result := bind(sh, sa, sizeof(sa));
    If result = SOCKET_ERROR Then Raise Exception.Create('bind failed');
    // ***************** BIND *******************
    }
    
    // Option: Header Include
    //only works with winsock2 from wsck.pas
    bOpt := 1;
    ret := SetSockOpt(sh, IPPROTO_IP, IP_HDRINCL, @bOpt, SizeOf(bOpt));
    if ret = SOCKET_ERROR then begin
      raise exception.create('setsockopt(IP_HDRINCL) failed: '+IntToStr(WSAGetLastError));
      exit;
    end;

    // Build the packet
    BuildUDPHeaders( FromIP ,  FromPort ,
                  ToIP, ToPort,
                  msg,
                  Buf,  iTotalSize );

    //remote
    remote.sin_family := AF_INET;
    remote.sin_port := htons(ToPort);
    remote.sin_addr.s_addr := inet_Addr(PansiChar(ansistring(ToIP  )));;
    // Send the packet
    ret := SendTo(sh, buf, iTotalSize, 0, Remote, SizeOf(Remote));
    if ret = SOCKET_ERROR then
      raise exception.create('sendto() failed: '+IntToStr(WSAGetLastError))
     else
      result:=ret;

    // Close socket
    CloseSocket(sh);
  finally
    // Close Winsock 2
    WSACleanup;
  end;
end;

end.
