import binascii
from genericpath import isdir
import glob
import hashlib
import json
import os
import struct
import zlib


class Buffer:
    def __init__(self, buff) -> None:
        self._buff = buff
        self._idx = 0

    def set_idx(self, idx) -> None:
        self._idx = idx

    def get_idx(self):
        return self._idx

    def read(self, size):
        buff = self._buff[self._idx:self._idx + size]
        self._idx += size
        return buff

    def readat(self):
        return self._buff[self._idx:]

    def read_at(self, size, off):
        return self._buff[off:size + off]

    def read_uleb(self):
        result, = struct.unpack('B', self.read(1))
        if result > 0x7f:
            cur, = struct.unpack('B', self.read(1))
            result = (result & 0x7f) | ((cur & 0x7f) << 7)
            if cur > 0x7f:
                cur, = struct.unpack('B', self.read(1))
                result |= (cur & 0x7f) << 14
                if cur > 0x7f:
                    cur, = struct.unpack('B', self.read(1))
                    result |= (cur & 0x7f) << 21
                    if cur > 0x7f:
                        cur, = struct.unpack('B', self.read(1))
                        result |= (cur & 0x7f) << 28
        return result


ACCESS_FLAGS = {
    0x1: 'public',
    0x2: 'private',
    0x4: 'protected',
    0x8: 'static',
    0x10: 'final',
    0x20: 'synchronized',
    0x40: 'bridge',             # 'volatile'
    0x80: 'varargs',            # 'transient'
    0x100: 'native',
    0x200: 'interface',
    0x400: 'abstract',
    0x800: 'strictfp',
    0x1000: 'synthetic',
    0x4000: 'enum',
    0x8000: 'unused',
    0x10000: 'constructor',
    0x20000: 'synchronized'
}


def get_access_flags_string(access_flags):
    result = []
    for ac in ACCESS_FLAGS:
        if access_flags & ac:
            result.append(ACCESS_FLAGS[ac])
    return ' '.join(result)


input_dir = './data/unzipped/'
output_dir = './outputs'
apk_folders = [apk_folder for apk_folder in os.listdir(input_dir) if os.path.isdir(os.path.join(input_dir, apk_folder))]

for apk_folder in apk_folders:
    output_folder = os.path.join(output_dir, apk_folder)
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)
    dex_files = glob.glob(os.path.join(input_dir, apk_folder, '*.dex'))
    for dex_file in dex_files:
        dex_name = os.path.basename(dex_file)[:-4]
        output_dex_folder = os.path.join(output_folder, dex_name)
        if not os.path.exists(output_dex_folder):
            os.makedirs(output_dex_folder)
        classes_file = os.path.join(output_dex_folder, 'classes.json')
        fields_file = os.path.join(output_dex_folder, 'fields.json')
        methods_file = os.path.join(output_dex_folder, 'methods.json')
        protos_file = os.path.join(output_dex_folder, 'protos.json')
        strings_file = os.path.join(output_dex_folder, 'strings.json')
        types_file = os.path.join(output_dex_folder, 'types.json')
        with open(dex_file, 'rb') as fp:
            buff = Buffer(fp.read())
        dex, version, checksum = struct.unpack('3sx3sxI', buff.read(12))
        assert checksum == zlib.adler32(buff.readat())
        sha1,  = struct.unpack('20s', buff.read(20))
        sha1 = binascii.hexlify(sha1).decode('ascii')
        assert sha1 == hashlib.sha1(buff.readat()).hexdigest()
        file_size, header_size, endian_tag = struct.unpack('III', buff.read(12))
        link_size, link_off, map_off = struct.unpack('III', buff.read(12))
        string_ids_size, string_ids_off = struct.unpack('II', buff.read(8))
        type_ids_size, type_ids_off = struct.unpack('II', buff.read(8))
        proto_ids_size, proto_ids_off = struct.unpack('II', buff.read(8))
        field_ids_size, field_ids_off = struct.unpack('II', buff.read(8))
        method_ids_size, method_ids_off = struct.unpack('II', buff.read(8))
        classes_size, classes_off = struct.unpack('II', buff.read(8))
        data_size, data_off = struct.unpack('II', buff.read(8))
        print('File name:', dex_file)
        print('File version:', dex.decode('ascii'), version.decode('ascii'))
        print('File size:', file_size)
        print('Adler32 checksum:', checksum)
        print('Sha1sum:', sha1)
        print('# of strings:', string_ids_size)
        print('# of types:', type_ids_size)
        print('# of protos:', proto_ids_size)
        print('# of fields:', field_ids_size)
        print('# of methods:', method_ids_size)
        print('# of classes:', classes_size)

        strings = []
        for i in range(string_ids_size):
            buff.set_idx(string_ids_off + i * 4)
            string_data_off, = struct.unpack('I', buff.read(4))
            buff.set_idx(string_data_off)
            string_size = buff.read_uleb()
            string_data, = struct.unpack('%ds' % string_size, buff.read(string_size))
            print(string_data)
            try:
                strings.append(string_data.decode('utf8'))
            except:
                strings.append('')
        with open(strings_file, 'w') as fp:
            json.dump(strings, fp, indent=2)

        type_strings = []
        buff.set_idx(type_ids_off)
        for i in range(type_ids_size):
            type_id, = struct.unpack('I', buff.read(4))
            type_string = strings[type_id]
            type_strings.append(type_string)

        with open(types_file, 'w') as fp:
            json.dump(type_strings, fp, indent=2)

        protos = []
        for i in range(proto_ids_size):
            parameters = []
            buff.set_idx(proto_ids_off + i * 12)
            shorty_id, \
                return_type_id, \
                parameters_off = struct.unpack('3I', buff.read(12))
            shorty_string = strings[shorty_id]
            return_type_string = type_strings[return_type_id]
            if parameters_off:
                buff.set_idx(parameters_off)
                parameters_size, = struct.unpack('I', buff.read(4))
                for j in range(parameters_size):
                    parameter_id, = struct.unpack('H', buff.read(2))
                    parameters.append(type_strings[parameter_id])
            protos.append({
                'shorty': shorty_string,
                'return_type': return_type_string,
                'parameters': parameters
            })

        with open(protos_file, 'w') as fp:
            json.dump(protos, fp, indent=2)

        fields = []
        buff.set_idx(field_ids_off)
        for i in range(field_ids_size):
            cls_id, \
                type_id, \
                name_id = struct.unpack('HHI', buff.read(8))
            cls_name = type_strings[cls_id]
            type_name = type_strings[type_id]
            field_name = strings[name_id]
            fields.append({
                'class': cls_name,
                'type': type_name,
                'name': field_name
            })

        with open(fields_file, 'w') as fp:
            json.dump(fields, fp, indent=2)


        methods = []
        buff.set_idx(method_ids_off)
        for i in range(method_ids_size):
            cls_id, proto_id, name_id = struct.unpack('HHI', buff.read(8))
            cls_name = type_strings[cls_id]
            proto = protos[proto_id]
            method_name = strings[name_id]
            methods.append({
                'class': cls_name,
                'proto': proto,
                'name': method_name
            })

        with open(methods_file, 'w') as fp:
            json.dump(methods, fp, indent=2)


        classes = []
        for i in range(classes_size):
            buff.set_idx(classes_off + 32 * i)
            cls_id, \
                access_flags, \
                supercls_id, \
                interfaces_off, \
                sourcefile_id, \
                annotation_off, \
                cls_data_off, \
                static_values_off = struct.unpack('8I', buff.read(32))
            cls_name = type_strings[cls_id]
            access_flags = get_access_flags_string(access_flags)
            supercls_name = type_strings[supercls_id]
            sourcefile_name = strings[sourcefile_id]
            cls_data = {}
            if cls_data_off:
                buff.set_idx(cls_data_off)
                static_fields_size = buff.read_uleb()
                instance_fields_size = buff.read_uleb()
                direct_methods_size = buff.read_uleb()
                virtual_methods_size = buff.read_uleb()
                static_fields = []
                instance_fields = []
                direct_methods = []
                virtual_methods = []

                prev_field_id = 0
                for _ in range(static_fields_size):
                    field_id = buff.read_uleb() + prev_field_id
                    prev_field_id = field_id
                    access_flags = buff.read_uleb()
                    static_fields.append({
                        'name': fields[field_id]['name'],
                        'type': fields[field_id]['type'],
                        'access_flags': get_access_flags_string(access_flags)
                    })

                prev_field_id = 0
                for _ in range(instance_fields_size):
                    field_id = buff.read_uleb() + prev_field_id
                    prev_field_id = field_id
                    access_flags = buff.read_uleb()
                    instance_fields.append({
                        'name': fields[field_id],
                        'type': fields[field_id]['type'],
                        'access_flags': get_access_flags_string(access_flags)
                    })

                for _ in range(direct_methods_size):
                    method_id = buff.read_uleb()
                    access_flags = buff.read_uleb()
                    code_off = buff.read_uleb()
                    method_name = methods[method_id]['name']
                    access_flags = get_access_flags_string(access_flags)
                    direct_methods.append({
                        'name': method_name,
                        'access_flags': access_flags,
                        'code_off': code_off
                    })

                for _ in range(virtual_methods_size):
                    method_id = buff.read_uleb()
                    access_flags = buff.read_uleb()
                    code_off = buff.read_uleb()
                    method_name = methods[method_id]['name']
                    access_flags = get_access_flags_string(access_flags)
                    virtual_methods.append({
                        'name': method_name,
                        'access_flags': access_flags,
                        'code_off': code_off
                    })

                for i in range(direct_methods_size):
                    code_off = direct_methods[i]['code_off']
                    if code_off:
                        buff.set_idx(code_off)
                        registers_size, ins_size, outs_size, tries_size, debug_info_off, insns_size = struct.unpack('4H2I', buff.read(16))
                        insns = list(struct.unpack('%dB' % insns_size * 2, buff.read(insns_size * 2)))
                        # TODO: extract dalvik bytecode
                        direct_methods[i]['code'] = insns
                    else:
                        direct_methods[i]['code'] = []

                for i in range(virtual_methods_size):
                    code_off = virtual_methods[i]['code_off']
                    if code_off:
                        buff.set_idx(code_off)
                        registers_size, ins_size, outs_size, tries_size, debug_info_off, insns_size = struct.unpack('4H2I', buff.read(16))
                        insns = list(struct.unpack('%dB' % insns_size * 2, buff.read(insns_size * 2)))
                        # TODO: extract dalvik bytecode
                        virtual_methods[i]['code'] = insns
                    else:
                        virtual_methods[i]['code'] = []

                cls_data['static_fields_size'] = static_fields_size
                cls_data['instance_fields_size'] = instance_fields_size
                cls_data['static_fields'] = static_fields
                cls_data['instance_fields'] = instance_fields
                cls_data['direct_methods_size'] = direct_methods_size
                cls_data['virtual_methods_size'] = virtual_methods_size
                cls_data['direct_methods'] = direct_methods
                cls_data['virtual_methods'] = virtual_methods

            classes.append({
                'name': cls_name,
                'access_flags': access_flags,
                'super_class': supercls_name,
                'sourcefile': sourcefile_name,
                'cls_data': cls_data
            })

        with open(classes_file, 'w') as fp:
            json.dump(classes, fp, indent=2)
