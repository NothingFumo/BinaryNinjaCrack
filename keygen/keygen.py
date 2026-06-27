import binascii
import base64
import hashlib
import json
import random
from Crypto.Cipher import ARC4
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Util.number import long_to_bytes,bytes_to_long
from Crypto.Hash import SHA256
from datetime import datetime, timezone

def get_time_str():
    utc_now = datetime.now(timezone.utc)
    iso_str = utc_now.isoformat(timespec='milliseconds')

    return iso_str

def gen_licdata():
    randdata=random.randbytes(0x100)
    k=hashlib.md5(randdata).digest()
    rc4=ARC4.new(key=k)
    rc4data=bytes.fromhex('9C2AAA09A4E2252B0BA125DB1E1CD272207D97CCA8446899')
    encdta=rc4.encrypt(rc4data)
    # print('rc4enc:',encdta.hex())

    ret=base64.standard_b64encode(randdata+encdta)
    # print('data:',ret)
    return ret
def gen_signature(msg,pri_data=bytes.fromhex('''308204A30201000282010100D2BF8069B298618B54272B13CE402C37826D906FA0DB47C916E304D61CFE847306AD1763A332A6FACBEF133DE5E634B333739EFFFE9F7513F7C38CDF4EB7CE27B56B728424F9410DB4CD3AB33D2A367123470D62324211876D83C15B59FB7A4D5A74E56F9E443DBEFF30289D3E4F84E58E6AB23AD4F43870034605E68EDF1FF90256AA027C6102981B8A7742C3DCFC536A4D98C4E22702F2BFFDE2985E232A2446D5750E20EDD27E59FA2475CFF2882CA33347209F62DED6965D85B03BDE6E02B99F680F33B7DC08F8730C0BCE62256FCA5613213A1182C00A36A9D496629D15C1B604550F97388C2DFD60CC8DC15CF5D61A829167CE07F9798168C92D6037470203010001028201005BC7FDC74A79D58565C5571BDD87921A2CA9C5ACEFCB7FD4622CC536F052A1E12C67A6978483F337A727FBE3C9A33B914D978D87E45E9290FB26C54B9D4F2C2F9BF16AE284EDAE78A72477EB867843547B6E1EB484B9C4438C1CC4D1217B855479D00DF9D1DDDB5C3A6BC14C55CE30CCFE7C96194C13FE1E3E36B92C234DA5F0B362663B5B353949FF83F3987080A20326CC8A4FC5E51FF5A91026BB72F1BF4EAA5EB893892E2AC6FEB828EC2D093F992589D7EDEE5DA8EA94C6F8EA61E1FF1D3686EE2B97859E0123CF438F457C97860C04263380EE82C84DB0CADCE121C93F5AD1EB0A802C7ABFF14B4265805CAC6C37F4BF4E17B034E29F3DE64EA98450CD02818100FFDC7E6D1275D1956316116CD79CD5A44F76A6284DD3C35E5A607C1C612D454BFB94DFF5EE63DDB695C8E3A9E398D188A25100959C632DBD3A23FC31F975484D1531151AA7CD6711C960018E366F1507FEB787757464F7E2F05AD097DAD9C8D34BAB3BD584948C7DABD750B3F9B651C3FCDE7133232CA2228F7880410A7FC89502818100D2DCBF521CC7FC91AE554A7ADE811CA07356C50227EC07A4DB06A2B681E29CA8F4D54A7D40D7DFAA38A1B6F03D9E4ACFBEF7C7AC45A6496C94BFD8FA0FB1C2528097AAACFDD0FAA5C9CD42A010018CB04A488A6437B5F4328B30D2FBE9290AA3C9937DD1DB92DFAE4431FC690B7EF879FFDDBAD9D3784A5869C6D8039B249D6B028181009A9EF0540FE4DD7C2EBE2657A5512516BFE2CEF4EA5B7FE4642F8CB145D4AADD093365C8E480BB7ADCB7E34546C29255C4E9B8B5B1258A7DA1461FE13F84ADE5CF59B30C41BDF27CA03A819624B52A7B8365FBD97236964B31BF5FF1751349B6CF32B2DD0CDB0CAFE18A243E2F390BDEA9D0EF8DDCC2DB5491695BF0725CD8A50281802101306917DC2DAA57D13DD131969FF67557358AFAD8B4F196DED9051C1B6E4DFBD48ECE402209FE48D2F7216F63A16E17040D9AE763F9C6271A484A0BBED51DB8C7048E03447C970A99383E7982E4948B6C034D6072F88018CD5198E08BEE006902CF04D40B8F3B65AD3546F3E7B1D8D6B5CC13604849CAC0F3C0C7FFB6A175028180616C870F1920FD24DEBE793A273591CB3E858962A9A93022AF36FB15CEF57F3C3EE101F1A8AF206DF757EC7A7EBD99D7E1C5B18870EB8B66E78F3FA005E4431D71B25F350103C2E68BC4474DF3BDAC57F8D9327304C65E5069DDB25C178615D1A3B264B22B8826E33D21F4CD50433FD6210ED5699741FB219E75F6DD8F5DB714''')):
    if isinstance(msg,str):
        msg=msg.encode()
    prik=RSA.import_key(pri_data)

    sig=pkcs1_15.new(prik)
    signature=sig.sign(SHA256.new(msg))
    ret=base64.standard_b64encode(signature)
    return ret
def kg(count:int,email:str,serial_hexstr:str=random.randbytes(0x10).hex()):
    lic={}
    lic["product"]= "Binary Ninja Personal"
    lic["email"]= email
    lic["serial"]= serial_hexstr
    lic["created"]=get_time_str()
    lic["type"]= "User"
    lic["count"]=count
    lic["data"]=gen_licdata().decode()
    msg='\x00'.join((lic["product"],lic["email"],lic["serial"],lic["created"],lic["type"],str(lic["count"]),lic["data"]))
    lic["signature"]= gen_signature(msg).decode()
    
    s=json.dumps(lic,indent=0)
    lic_text='[\n%s\n]'%s
    return lic_text

def build_pattern_instructions():
    pattern_instrs = []
    pattern_instrs.append([0xC7, 0x00, None, None, None, None])

    offset = 0x04
    while offset <= 0x7C:
        pattern_instrs.append([0xC7, 0x40, offset, None, None, None, None])
        offset += 4

    offset = 0x80
    while offset <= 0xFC:
        pattern_instrs.append([0xC7, 0x80, offset, 0x00, 0x00, 0x00,
                               None, None, None, None])
        offset += 4

    while offset <= 0x124:
        offset_temp = offset - 0x100
        pattern_instrs.append([0xC7, 0x80, offset_temp, 0x01, 0x00, 0x00,
                               None, None, None, None])
        offset += 4

    return pattern_instrs

def find_xor_key(binary, end_offset, search_bytes=100):
    i = end_offset
    max_offset = min(len(binary), i + search_bytes)

    while i < max_offset - 5:  # xor reg, imm32 is 6 bytes
        opcode = binary[i]
        modrm = binary[i + 1]
        
        if opcode == 0x35 and (modrm >> 3) & 7 == 6:
            imm_bytes = binary[i + 1:i + 5]
            xor_key = int.from_bytes(imm_bytes, "little")
            return xor_key
        elif opcode == 0x81 and (modrm >> 3) & 7 == 6:
            imm_bytes = binary[i + 2:i + 6]
            xor_key = int.from_bytes(imm_bytes, "little")
            return xor_key
        i += 1
    return None

def find_xor_key_backup(binary, end_offset, search_bytes=150):
    i = end_offset
    max_offset = min(len(binary), i + search_bytes)
    reg_map = {}

    while i < max_offset - 5:
        opcode = binary[i]

        if opcode == 0x35 and (modrm >> 3) & 7 == 6:
            imm_bytes = binary[i + 1:i + 5]
            xor_key = int.from_bytes(imm_bytes, "little")
            if xor_key is not None:
                return xor_key

        if 0xB8 <= opcode <= 0xBF:
            reg = opcode - 0xB8
            imm_bytes = binary[i + 1:i + 5]
            imm_value = int.from_bytes(imm_bytes, "little")
            reg_map[reg] = imm_value
            i += 5
            continue

        if opcode == 0x81:
            modrm = binary[i + 1]
            if (modrm >> 3) & 7 == 6:
                imm_bytes = binary[i + 2:i + 6]
                xor_key = int.from_bytes(imm_bytes, "little")
                if xor_key is not None:
                    return xor_key

        if opcode == 0x31:
            modrm = binary[i + 1]
            reg_dest = modrm & 7
            reg_src = (modrm >> 3) & 7
            if reg_src in reg_map:
                xor_key = reg_map[reg_src]
                if xor_key is not None:
                    return xor_key
        i += 1
    return None

def search_pattern_operand_locations(binary, pattern_instrs, max_gap):
    n = len(binary)
    first_instr = pattern_instrs[0]
    plen = len(first_instr)

    i = 0
    while i <= n - plen:
        operand_locations = []
        match = True

        instr_locs = []
        for j in range(plen):
            if first_instr[j] is None:
                instr_locs.append(i + j)
            else:
                if binary[i + j] != first_instr[j]:
                    match = False
                    break

        if not match:
            i += 1
            continue

        operand_locations.append(instr_locs)
        last_pos = i

        for instr in pattern_instrs[1:]:
            instr_len = len(instr)
            found = False

            search_limit = min(last_pos + 1 + max_gap, n - instr_len + 1)

            for k in range(last_pos + 1, search_limit):
                sub_match = True
                instr_locs = []

                for l in range(instr_len):
                    if instr[l] is None:
                        instr_locs.append(k + l)
                    else:
                        if binary[k + l] != instr[l]:
                            sub_match = False
                            break

                if sub_match:
                    operand_locations.append(instr_locs)
                    last_pos = k
                    found = True
                    break

            if not found:
                match = False
                break

        if match:
            return i, operand_locations

        i += 1

    return None, None

def transform(table, length, xor_key):
    dst = bytearray(length)
    p = 0

    for i in range(length):
        rax = i >> 2
        edx = table[rax] ^ xor_key
        shift = (i & 3) << 3
        byte = (edx >> shift) & 0xFF

        dst[p] = byte
        p += 1

    return bytes(dst)

if __name__ == '__main__':
    files = [
        "libbinaryninjacore.so.1",
        "libbinaryninjacore.1.dylib",
        "binaryninjacore.dll"
    ]
    for filename in files:
        try:
            with open(filename, "r+b") as f:
                data = f.read()

                pattern_instrs = build_pattern_instructions()

                offset, operand_locations = search_pattern_operand_locations(data, pattern_instrs, max_gap=32) # add more if pattern not found

                if offset is None:
                    print("Pattern not found.")
                    exit()

                all_offsets = [loc for group in operand_locations for loc in group]
                print("Total operand byte positions:", len(all_offsets))

                end_of_pattern = max(max(group) for group in operand_locations) + 1
                xor_key = find_xor_key(data, end_of_pattern)
                if xor_key is None:
                    xor_key = find_xor_key_backup(data, end_of_pattern)
                print(hex(xor_key))
                pub_data=bytes.fromhex('''30820122300D06092A864886F70D01010105000382010F003082010A0282010100D2BF8069B298618B54272B13CE402C37826D906FA0DB47C916E304D61CFE847306AD1763A332A6FACBEF133DE5E634B333739EFFFE9F7513F7C38CDF4EB7CE27B56B728424F9410DB4CD3AB33D2A367123470D62324211876D83C15B59FB7A4D5A74E56F9E443DBEFF30289D3E4F84E58E6AB23AD4F43870034605E68EDF1FF90256AA027C6102981B8A7742C3DCFC536A4D98C4E22702F2BFFDE2985E232A2446D5750E20EDD27E59FA2475CFF2882CA33347209F62DED6965D85B03BDE6E02B99F680F33B7DC08F8730C0BCE62256FCA5613213A1182C00A36A9D496629D15C1B604550F97388C2DFD60CC8DC15CF5D61A829167CE07F9798168C92D6037470203010001''')
                table = [int.from_bytes(pub_data[i:i+4], "little") for i in range(0, len(pub_data), 4)]
                length = 0x128

                xored_pubkey_modded = transform(table, length, xor_key)

                if len(xored_pubkey_modded) != len(all_offsets):
                    raise ValueError("Transformed key length does not match operand count!")

                for idx, file_offset in enumerate(all_offsets):
                    f.seek(file_offset)
                    f.write(bytes([xored_pubkey_modded[idx]]))

            # generate license, thank you DirWang https://www.cnblogs.com/DirWang/p/19016924
            lic_path='license.dat' 
            count=32
            email="hi@binja.com"
            text=kg(count,email)
            with open(lic_path,'w',encoding='utf8') as f:
                f.write(text)
            print("Patched and made license for " + filename)
        except FileNotFoundError as e:
            print(filename + " not found, skipping.")
        except PermissionError as e:
            print("No permisions to edit/open " + filename)