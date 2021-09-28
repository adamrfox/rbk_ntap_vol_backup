#!/usr/bin/python

from __future__ import print_function
import sys
import getopt
import getpass
import collections
import rubrik_cdm
from datetime import datetime
import urllib3
urllib3.disable_warnings()
sys.path.append('./NetApp')
from NaServer import *
import ssl

def usage():
    sys.stderr.write("Usage: rbk_ntap_vol_backup.py: [-hD] [-c rubrik_creds] [-t Rbk API token] [-n NTAP creds] [-m map_file] ntap rubrik\n")
    sys.stderr.write("-h : --help : Prints Usage\n")
    sys.stderr.write("-c | --rubrik_creds= : Rubrik login creds [user:password]\n")
    sys.stderr.write("-t | --token= : Rubrik API token\n")
    sys.stderr.write("-n | --ntap_creds= : NetApp Creds [user:password]\n")
    sys.stderr.write("-m | --map_file= : name of SVM map file [def: svm_map.csv]\n")
    sys.stderr.write("ntap : Name or IP of the NetApp Cluster Management LIF\n")
    sys.stderr.write("rubrik : Name of IP of the Rurbik\n")
    exit(0)

def dprint(message):
    if DEBUG:
        dfp = open(debug_file, "a")
        dfp.write(message + "\n")
        dfp.close()

def ntap_set_err_check(out):
    if(out and (out.results_errno() != 0)) :
        r = out.results_reason()
        print("Connection to filer failed" + r + "\n")
        sys.exit(2)

def ntap_invoke_err_check(out, call):
    if(out.results_status() == "failed"):
            print( "NTAP API CALL: " + call + " failed: " + str(out.results_reason()) + "\n")
            sys.exit(2)
def python_input(message):
    if int(sys.version[0]) > 2:
        val = input(message)
    else:
        val = raw_input(message)
    return(val)

def get_svm_map(svm_map_file):
    with open(svm_map_file) as fp:
        for line in fp:
            line = line.rstrip()
            if not line or line.startswith('#'):
                continue
            lf = line.split(',')
            svm_map[lf[0]] = lf[1]
    fp.close()
    return(svm_map)

def is_exception(vol_exceptions, svm, vol):
    for ve in vol_exceptions:
        if ve['host'] == svm_map[svm] and ve['vol'] == vol:
            return(True)
    return(False)

def purge_lists(qtree_list, vol_list):
    new_qtree_list = {}
    new_vol_list = {}
    vf = []
    vol_exceptions = []
    dprint("\nOLD VOL LIST: " + str(vol_list))
    if CUSTOMER_MODS:
        try:
            ef = open(exceptions_file, "r")
            for line in ef:
                line = line.rstrip()
                if not line or line.startswith('#'):
                    continue
                lf = line.split(':')
                ve_inst = {}
                for svm in svm_map:
                    if svm_map[svm] == lf[0]:
                        ve_inst = {'host': lf[0], 'vol': lf[1]}
                        break
                if not ve_inst:
                    sys.stderr.write("Can't map hostname: " + lf[0] + "to an SVM.  Skipping exception\n")
                    continue
                vol_exceptions.append(ve_inst)
            ef.close()
            dprint("VOL_EXCEPT: " + str(vol_exceptions))
        except:
            pass
    for svm in vol_list:
        for vol in vol_list[svm]:
            if CUSTOMER_MODS:
                vf = vol.split('_')
                try:
                    if 'b' not in vf[2]:
                        if not vol_exceptions or not is_exception(vol_exceptions, svm, vol):
                            dprint("Purging vol " + vol + ": bad pattern/not exception")
                            continue
                except IndexError:
                    if not vol_exceptions or not is_exception(vol_exceptions, svm, vol):
                        dprint("Puring vol " + vol + ": bad pattern/not exception [2]")
                        continue
            if vol_list[svm][vol]['unix_qtree'] and vol_list[svm][vol]['ntfs_qtree']:
                try:
                    new_vol_list[svm][vol] = {'path': vol_list[svm][vol]['path']}
                except:
                    new_vol_list[svm] = {}
                    new_vol_list[svm][vol] = {'path': vol_list[svm][vol]['path']}
            else:
                dprint("Puring vol " + vol + ": no mixed trees")

    dprint("\nOLD_QTREE_LIST:" + str(qtree_list))
    for svm in qtree_list:
        for vol in qtree_list[svm]:
            try:
                new_vol_list[svm][vol]
            except:
                continue
            try:
                new_qtree_list[svm]
            except:
                new_qtree_list[svm] = {}
            new_qtree_list[svm][vol] = {}
            new_qtree_list[svm][vol] = qtree_list[svm][vol]
    return(new_qtree_list, new_vol_list)

def get_svm_name(map, host):
    for m in map:
        if map[m] == host:
            return(m)
    return("")

def valid_share(svm, vol, path, vol_list):
    try:
        vol_list[svm][vol]
    except:
        return(False)
    if vol_list[svm][vol]['path'] == path:
        return(True)
    return(False)

def valid_rubrik_share(h_data, map, share_list, vol_list):
    if h_data['hostname'] not in map.values():
        return(False)
    svm_name = get_svm_name(map, h_data['hostname'])
    try:
        vol_list[svm_name]
    except:
        return(False)
    if h_data['shareType'] == "NFS":
        for v in vol_list[svm_name]:
            if vol_list[svm_name][v]['path'] == h_data['exportPoint']:
                return(True)
        return(False)
    for s in share_list[svm_name]:
        if share_list[svm_name][s]['name'] == h_data['exportPoint']:
            return(True)
    return(False)

def get_vol_name_from_rbk_share_list(rbk_sh_svm, rbk_sh, share_list, vol_list):
    dprint("GET_VOL: " + str(rbk_sh))
    if rbk_sh['protocol'] == "NFS":
        for v in vol_list[rbk_sh_svm]:
            if vol_list[rbk_sh_svm][v]['path'] == rbk_sh['name']:
                return(v)
        return("")
    dprint("SMB_SHARE")
    for v in share_list[rbk_sh_svm]:
        if share_list[rbk_sh_svm][v]['name'] == rbk_sh['name']:
            vol = get_vol_from_path(vol_list, rbk_sh_svm, share_list[rbk_sh_svm][v]['path'])
            dprint("SMB_VOL=" + vol)
            return(vol)
    return("")

def create_fs_template(fst_host, fst_vol, fst_proto):
    name = '_'.join([fst_host, fst_vol, fst_proto])
    if fst_proto == "NFS":
        payload = [{"includes": ["x"], "excludes": [".snapshot"], "name": name, "shareType": "NFS", "allowBackupHiddenFoldersInNetworkMounts": True}]
    else:
        payload = [{"includes": ["x"], "excludes": ["~snapshot"], "name": name, "shareType": "SMB"}]
    return(payload)

def get_vol_from_path(vol_list, svm_name, path):
    for v in vol_list[svm_name]:
        if vol_list[svm_name][v]['path'] == path:
            return(v)
    return("")

def log_write(name, message):
    fp = open(name, "a")
    fp.write(message + "\n")
    fp.close()
    return

if __name__ == "__main__":
    ntap_user = ""
    ntap_password = ""
    rubrik_user = ""
    rubrik_password = ""
    token = ""
    svm_map_file = "svm_map.csv"
    log_file = ""
    DEBUG = False
    svm_list = []
    vol_list = {}
    svm_map = {}
    qtree_list = {}
    share_list = {}
    rubrik_share_list = {}
    timeout = 60
    NAS_DA = False
    CUSTOMER_MODS = True
    exceptions_file = "vol_exceptions.txt"
    debug_file = "debug_data.txt"

    optlist, args = getopt.getopt(sys.argv[1:], 'Dc:t:n:hm:M', ['--DEBUG', '--rubrik_creds=', '--ntap_creds=',
                                                                 '--token=', '--help', '--mapfile=', '--mods'])
    for opt, a in optlist:
        if opt in ('-D', '--DEBUG'):
            DEBUG = True
            dfp = open(debug_file, "w")
            dfp.close()
        if opt in ('-c', '--rubrik_creds'):
            (rubrik_user, rubrik_password) = a.split(':')
        if opt in ('-n', '--ntap_creds'):
            (ntap_user, ntap_password) = a.split(':')
        if opt in ('-t', '--token'):
            token = a
        if opt in ('-h', '--help'):
            usage()
        if opt in ('-m', '--mapfile'):
            svm_map_file = a
        if opt in ('-M', '--mods'):
            CUSTOMER_MODS = False

    try:
        (ntap_host, rubrik_host) = args
    except:
        usage()
    svm_map = get_svm_map(svm_map_file)
    dprint("SVM_ MAP: " + str(svm_map))
    if not token:
        if not rubrik_user:
            rubrik_user = python_input("Rubrik User: ")
        if not rubrik_password:
            rubrik_password = getpass.getpass("Rubrik Password: ")
        rubrik = rubrik_cdm.Connect(rubrik_host, rubrik_user, rubrik_password)
    else:
        rubrik = rubrik_cdm.Connect(rubrik_host, api_token=token)
    if not ntap_user:
        ntap_user = python_input("NTAP User: ")
    if not ntap_password:
        ntap_password = getpass.getpass("NTAP Password: ")
    try:
        _create_unverified_https_context = ssl._create_unverified_context
    except AttributeError:
        pass
    else:
        ssl._create_default_https_context = _create_unverified_https_context
    netapp = NaServer(ntap_host, 1, 130)
    out = netapp.set_transport_type('HTTPS')
    ntap_set_err_check(out)
    out = netapp.set_style('LOGIN')
    ntap_set_err_check(out)
    out = netapp.set_admin_user(ntap_user, ntap_password)
    ntap_set_err_check(out)
    dprint(str(svm_map.keys()))
    print("Gathering Qtree Info from NetApp")
    zapi = NaElement('volume-get-iter')
    xi = NaElement('desired-attributes')
    zapi.child_add(xi)
    xi1 = NaElement('volume-attributes')
    xi.child_add(xi1)
    xi2 = NaElement('volume-id-attributes')
    xi1.child_add(xi2)
    xi2.child_add_string('junction-path', '<junction-path>')
    xi2.child_add_string('name', '<name>')
    xi2.child_add_string('owning-vserver-name', '<owning-vserver-name>')
    zapi.child_add_string("max-records", 100000)
    out = netapp.invoke_elem(zapi)
    ntap_invoke_err_check(out, "volume-get-iter")
    vol_attrs = out.child_get('attributes-list').children_get()
    for v in vol_attrs:
        vid_attrs = v.child_get('volume-id-attributes')
        volume = vid_attrs.child_get_string('name')
        junction = vid_attrs.child_get_string('junction-path')
        junct_point = junction
        vol_svm = vid_attrs.child_get_string('owning-vserver-name')
        dprint("VOL: " + volume + " // " + "SVM: " + vol_svm)
        if vol_svm not in svm_map.keys():
            dprint("Skipping " + vol_svm + ":" + volume + ": not in map file")
            continue
        try:
            dprint("ADDING VOL: " + volume)
            vol_list[vol_svm][volume] = {'path': junct_point,  'unix_qtree': False, 'ntfs_qtree': False}
        except:
            dprint("ADDING NEW VOL:" + volume)
            vol_list[vol_svm] = {}
            vol_list[vol_svm][volume] = {'path': junct_point,  'unix_qtree': False, 'ntfs_qtree': False}
    zapi = NaElement('qtree-list-iter')
    xi = NaElement('desired-attributes')
    zapi.child_add(xi)
    xi1 = NaElement('qtree-info')
    xi.child_add(xi1)
    xi1.child_add_string('qtree', '<qtree>')
    xi1.child_add_string('security-style', '<security-style>')
    xi1.child_add_string('volume', '<volume>')
    xi1.child_add_string('vserver', '<vserver>')
    zapi.child_add_string('max-records', 100000)
    out = netapp.invoke_elem(zapi)
    ntap_invoke_err_check(out, "qtree-list-iter")
    qtree_attrs = out.child_get('attributes-list').children_get()
    for q in qtree_attrs:
        q_path = q.child_get_string('qtree')
        if not q_path:
            continue
        q_sec = q.child_get_string('security-style')
        q_vol = q.child_get_string('volume')
        q_svm = q.child_get_string('vserver')
        dprint("QTREE CHECK: SVM: " + q_svm + " // VOL: " + q_vol + " // PATH: " + q_path)
        if q_sec == "unix":
            try:
                vol_list[q_svm][q_vol]['unix_qtree'] = True
            except:
                continue
        else:
            try:
                vol_list[q_svm][q_vol]['ntfs_qtree'] = True
            except:
                continue
        try:
            qtree_list[q_svm][q_vol][q_path] = {'security': q_sec}
        except:
            try:
                qtree_list[q_svm]
            except:
                qtree_list[q_svm] = {}
            try:
                qtree_list[q_svm][q_vol]
            except:
                qtree_list[q_svm][q_vol] = {}
            qtree_list[q_svm][q_vol][q_path] = {'security': q_sec}
    (qtree_list, vol_list) = purge_lists(qtree_list, vol_list)
    dprint("\nVOL_LIST: " + str(vol_list))
    dprint("\nQTREE_LIST: " + str(qtree_list))
    print("Gathering Shares from NetApp")
    zapi = NaElement('cifs-share-get-iter')
    xi = NaElement('desired-attributes')
    zapi.child_add(xi)
    xi1 = NaElement('cifs-share')
    xi.child_add(xi1)
    xi1.child_add_string('path', '<path>')
    xi1.child_add_string('share-name', '<share-name>')
    xi1.child_add_string('volume', '<volume>')
    xi1.child_add_string('vserver', '<vserver>')
    zapi.child_add_string('max-records', 100000)
    out = netapp.invoke_elem(zapi)
    ntap_invoke_err_check(out, "cifs-share-get-iter")
    shares_attrs = out.child_get('attributes-list').children_get()
    for share in shares_attrs:
        sh_path = share.child_get_string('path')
        sh_name = share.child_get_string('share-name')
        sh_vol = share.child_get_string('volume')
        sh_svm = share.child_get_string('vserver')
        if sh_svm not in svm_map.keys():
            continue
        if not valid_share(sh_svm, sh_vol, sh_path, vol_list):
            continue
        try:
            share_list[sh_svm][sh_name] = {'path': sh_path, 'name': sh_name}
        except:
            share_list[sh_svm] = {}
            share_list[sh_svm][sh_name] = {'path': sh_path, 'name': sh_name}
    dprint("\nSHARES: " + str(share_list))
    print("Gathering Share Info From Rubrik")
    hs_data = rubrik.get('internal', '/host/share', timeout=timeout)
    for hs in hs_data['data']:
        if hs['hostname'] not in svm_map.values():
            continue
        if hs['status'] == "REPLICATION_TARGET":
            continue
        if not valid_rubrik_share(hs, svm_map, share_list, vol_list):
           continue
        svm_name = get_svm_name(svm_map, hs['hostname'])
        get_vol_from_path(vol_list, svm_name, hs['exportPoint'])
        rub_share_inst = {'sh_id': hs['id'], 'h_id': hs['hostId'], 'hostname': hs['hostname'],
                          'protocol': hs['shareType'], 'name': hs['exportPoint']}
        try:
            rubrik_share_list[get_svm_name(svm_map, hs['hostname'])].append(rub_share_inst)
        except:
            rubrik_share_list[get_svm_name(svm_map, hs['hostname'])] = []
            rubrik_share_list[get_svm_name(svm_map, hs['hostname'])].append(rub_share_inst)
    dprint("\nRBK_SHARES: " + str(rubrik_share_list))
    print("Checking and Updating Rubrik Fileset Templates")
    now = datetime.now()
    now_s = now.strftime("%Y-%m-%dT%H.%M.%S")
    log_file = "qtree_fileset_log_" + now_s + ".log"
    fp = open(log_file, "w")
    fp.close()
    for rbk_sh_svm in rubrik_share_list:
        for rbk_sh in rubrik_share_list[rbk_sh_svm]:
            fs_info = {}
            vol_name = get_vol_name_from_rbk_share_list(rbk_sh_svm, rbk_sh, share_list, vol_list)
            fs_template_name = str(svm_map[rbk_sh_svm] + '_' + vol_name + '_' + rbk_sh['protocol'])
            fs_info = rubrik.get('v1', '/fileset_template?name=' + fs_template_name, timeout=timeout)
            if fs_info['total'] == 0:
                print("Creating new fileset template: " + fs_template_name)
                payload = create_fs_template(svm_map[rbk_sh_svm], vol_name, rbk_sh['protocol'])
                new_fst = rubrik.post('internal', '/fileset_template/bulk', payload, timeout=timeout)
                log_write(log_file, "TEMPLATE_CREATE," + fs_template_name)
                dprint(str(new_fst))
                if new_fst['total'] == 0:
                    sys.stderr.write("Error creating fileset template: " + fs_template_name + "\n")
                    continue
                fs_info = new_fst
                payload = [{'isPassthrough': NAS_DA, 'enableSymlinkResolution': False, 'enableHardlinkSupport': False,
                           'shareId': rbk_sh['sh_id'], 'templateId': fs_info['data'][0]['id']}]
                fs_inst = rubrik.post("internal", "/fileset/bulk", payload, timeout=60)
                log_write(log_file, "TEMPLATE_ADD," + fs_template_name + "," + rbk_sh['name'])
                dprint("FS_INST = " + str(fs_inst))
            fst_id = fs_info['data'][0]['id']
            dprint(fs_info['data'][0]['name'] + " : " + str(fst_id))
            include_list = []
            if rbk_sh['protocol'] == "NFS":
                v_name = get_vol_name_from_rbk_share_list(rbk_sh_svm, rbk_sh, share_list, vol_list)
                for q in qtree_list[rbk_sh_svm][v_name]:
                    if qtree_list[rbk_sh_svm][v_name][q]['security'] == "unix":
                        include_list.append("/" + q + "/**")
            else:
                v_name = get_vol_name_from_rbk_share_list(rbk_sh_svm, rbk_sh, share_list, vol_list)
                for q in qtree_list[rbk_sh_svm][v_name]:
                    if qtree_list[rbk_sh_svm][v_name][q]['security'] != "unix":
                        include_list.append("\\" + q + "\\**")
            if collections.Counter(include_list) == collections.Counter(fs_info['data'][0]['includes']):
                print("Template: " + fs_info['data'][0]['name'] + " : " + "OK")
                log_write(log_file, "TEMPLATE_STATUS," + fs_info['data'][0]['name'] + ",No Change")
                continue
            fs_info['data'][0]['includes'] = include_list
            print("Updating Fileset Template: " + fs_info['data'][0]['name'])
            dprint("\n" + str(fs_info['data'][0]))
            new_fs = rubrik.patch('v1', '/fileset_template/' + str(fs_info['data'][0]['id']), fs_info['data'][0], timeout=timeout)
            log_write(log_file, "TEMPLATE_UPDATE," + fs_info['data'][0]['name'] + "," + str(fs_info['data'][0]['includes']))
            dprint("\nPATCH: " + str(new_fs))
