from socket import IPPROTO_TCP
from grader.iputils import read_ipv4_header
from audioop import reverse
from grader.tcputils import calc_checksum, str2addr
from iputils import *
from cgi import test
from doctest import debug_script
import struct

class IP:
    def __init__(self, enlace):
        """
        Inicializa a camada de rede. Recebe uma implementação de camada de enlace
        capaz de localizar os next_hop, como Ethernet com ARP.
        """
        self.table = {}
        self.id = 0
        self.proximity = -1
        self.callback = None
        self.enlace = enlace
        self.enlace.registrar_recebedor(self.__raw_recv)
        self.ignore_checksum = self.enlace.ignore_checksum
        self.meu_endereco = None

    def __raw_recv(self, datagrama):
        dscp, ecn, identificacao, flags, frag_offset, ttl, proto, \
            src_addr, dst_addr, payload = read_ipv4_header(datagrama)

        if dst_addr == self.meu_endereco:
            # atua como host
            if proto == IPPROTO_TCP and self.callback:
                self.callback(src_addr, dst_addr, payload)
        else:
            # atua como roteador
            self.proximity = -1
            next_hop = self._next_hop(dst_addr)
            
            # Extração
            ver_ihl, dscpecn, comprimento, _, flg_offset, _, protocolo, checksum, ip_origem, ip_destino = struct.unpack('!BBHHHBBHII', datagrama[:20]) 
            infos = [ver_ihl, dscpecn, comprimento, self.id, flg_offset, ttl, protocolo, 0, ip_origem, ip_destino]
            
            if ttl > 1:
                datagrama = self.montar_datagrama(payload, None, infos)
                
            else:
                proto_num = 1
                self.proximity = -1
                next_hop = self._next_hop(src_addr)
                daddress = next_hop
                
                if self.proximity == 0:
                    daddress = src_addr
                
                sipInt, = struct.unpack('!I', str2addr(self.meu_endereco))
                dipInt, = struct.unpack('!I', str2addr(daddress))

                infos = [ver_ihl, dscpecn, comprimento, self.id, flg_offset, 64, proto_num, 0, sipInt, dipInt]

                #Construção Tempo Excedido
                icmp_checksum = 0

                ihl = ver_ihl & 0xf
                # Calculo
                header = struct.pack('!BBHI', 0x0b, 0, icmp_checksum, 0) + (datagrama[:(4 * (ihl) + 8)])
                icmp_checksum = calc_checksum(header)
                header = struct.pack('!BBHI', 0x0b, 0, icmp_checksum, 0) + (datagrama[:(4 * (ihl) + 8)])
                
                # Atualiza o tamanho do datagrama
                infos[2] = 20 + len(header)

                # Monta o datagrama final
                datagrama = self.montar_datagrama(header, None, infos)

                self.enlace.enviar(datagrama, next_hop)
                return

            self.enlace.enviar(datagrama, next_hop)

    def _next_hop(self, dest_addr):
        dest, = struct.unpack('!I', str2addr(dest_addr))
        for cidr_val in self.table.keys():
            cidr, bits_ignorar = cidr_val.split('/')
            ignored = 32 - int(bits_ignorar)
            prefix, = struct.unpack('!I', str2addr(cidr))
            prefix = prefix >> ignored << ignored
            sample = dest >> ignored << ignored

            if sample == prefix:
                self.proximity = int(bits_ignorar)
                return self.table[cidr_val]

    def definir_endereco_host(self, meu_endereco):
        """
        Define o endereço IPv4 (string no formato x.y.z.w) deste host.
        Se recebermos datagramas destinados a outros endereços, atuaremos como roteador.
        """
        self.meu_endereco = meu_endereco

    def definir_tabela_encaminhamento(self, tabela):
        """
        Define a tabela de encaminhamento com o formato
        [(cidr0, next_hop0), (cidr1, next_hop1), ...]

        Onde os CIDR são fornecidos como 'x.y.z.w/n', e os
        next_hop como 'x.y.z.w'.
        """

        if len(self.table) >= 0: 
            self.table.clear()

        tabela.sort(key=lambda rota: int(rota[0].split('/')[1]), reverse=True)
       
        for rota in tabela:
            self.table[rota[0]] = rota[1]

    def registrar_recebedor(self, callback):
        """
        Registra uma função a ser chamada quando dados chegarem
        da camada de rede.
        """
        self.callback = callback

    def enviar(self, segmento, dest_addr):
        """
        Envia segmento para dest_addr, onde dest_addr é um endereço IPv4
        (string no formato x.y.z.w).
        """
        self.proximity = -1
        next_hop = self._next_hop(dest_addr)
        
        datagrama = self.montar_datagrama(segmento, dest_addr, [])

        self.enlace.enviar(datagrama, next_hop)

    def montar_datagrama(self, segmento, dest_addr, infos):
        if not infos:
            sip, = struct.unpack('!I', str2addr(self.meu_endereco))
            dip, = struct.unpack('!I', str2addr(dest_addr))
            ver_ihl = 0x45
            dscpecn = 0x00
            size = 20 + len(segmento)
            flg_offset = 0x00 
            ttl = 64
            protocolo = 6
            hchecksum = 0
            id = self.id
            self.id += size
        else:
            ver_ihl, dscpecn, size, id, flg_offset, ttl, protocolo, hchecksum, sip, dip = infos
            ttl -= 1
        
        cip = struct.pack('!BBHHHBBHII', ver_ihl, dscpecn, size, id, flg_offset, ttl, protocolo, hchecksum, sip, dip)
        hchecksum = calc_checksum(cip)
        
        cip = struct.pack('!BBHHHBBHII', ver_ihl, dscpecn, size, id, flg_offset, ttl, protocolo, hchecksum, sip, dip) 
        
        datagrama = cip + segmento

        return datagrama