import re
import sys
import json
import pprint
import codecs
import jsondiff
import argparse
import difflib
import itertools
import logging
from itertools import izip_longest as zip_longest
from jsondiff import diff


import traceback


file_path = r"/home/psadmin/tests/upd_autotests/resources/dump/pcaps_and_jsons/anotherjson.json"
#file_path = r"/home/psadmin/tests/upd_autotests/resources/dump/pcaps_and_jsons/dv-dra-gy2_03062025_2.json"
another_file_path = r"/home/psadmin/tests/upd_autotests/resources/dump/pcaps_and_jsons/dv-dra-gy2_03062025_2.json"
#another_file_path = r"/home/psadmin/tests/upd_autotests/resources/dump/pcaps_and_jsons/anotherjson.json"
#another_file_path = r"/home/psadmin/tests/upd_autotests/resources/dump/pcaps_and_jsons/dump_merge.json"
yet_another_path = r"/home/psadmin/tests/upd_autotests/resources/dump/pcaps_and_jsons/dump_merge.json"

with open(file_path, "r") as file1:
    data1 = json.load(file1, object_pairs_hook=lambda pairs: pairs)
with open(another_file_path, "r") as file2:
    data2 = json.load(file2, object_pairs_hook=lambda pairs: pairs)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filename = "output.log",
    filemode = 'w'
#    handlers=[
#        logging.FileHandler("output.log"),
#        logging.StreamHandler()
#    ]
)

class Tee:
    def __init__(self, *files):
        self.files = files
    def write(self, obj):
        for f in self.files:
            f.write(obj)
            f.flush()
    def flush(self):
        for f in self.files:
            f.flush()

class Comparison:
  
  def __init__(self, args):
      self.data1 = data1
      self.data2 = data2
      self.warn = args.warn
      self.ignore_codes = args.ignore
  
  def decode_avp(self, obj):
    try:
      obj = codecs.decode(obj.replace(":",""), 'hex').decode('ascii')
    except:
      pass
    return obj

  def tuple_to_dict(self, data):
    if isinstance(data, list):
        result = {}
        for key, value in data:
            if isinstance(value, list):
                value = dict(json.loads(json.dumps(value, indent = 4)))
                result[key] = value
                return result
            else:
                return data
                #result[key] = value
    else:
        return data


  def start_diff(self):
      print("================================================================================================================")
      diff_result = json.dumps(self.data1)
      with open(yet_another_path, 'w') as file3:
          file3.write(json.dumps(diff_result))
      diff_result = pprint.pformat(diff_result, indent=1)
  
  def start_count(self):
      print("================================================================================================================")
      if(len(self.data1))!=(len(self.data2)):
          print('DIFFERENT NUMBER OF PACKETS!')
          print('DUMP #1 CONTAINS: ' + str(len(self.data1)) + ' PACKETS')
          print('    FILE PATH: ' + str(file_path))
          print('DUMP #2 CONTAINS: ' + str(len(self.data2)) + ' PACKETS')
          print('    FILE PATH: ' + str(another_file_path))
      else:
          print('AMOUNTS OF PACKETS IN BOTH DUMPS ARE EQUAL')

  def parsing_avp_file(self):
    obj = r"./AvpCodes"
    parsed_avp_codes = []
    with open("{}".format(obj), "r") as _file:
      descriptive_avp_codes =_file.readlines()
    for item in descriptive_avp_codes:
      item = item.split()
      parsed_avp_codes.append(item)
    return parsed_avp_codes

  def parsing_avps(self, obj):
          res_message = []
          no = 0
          print("================================================================================================================")
          print(" ")
          for _packet in obj:
              _tuple = {}
              _keys = ("layers", "diameter")
              no += 1
              packet_avps = []
              print("PACKET #{}".format(no))
              print(" ")
              avp, avp_code, result_message = [], [], []
              _packet = json.dumps(_packet, indent=4)
              _packet = dict(json.loads(_packet))
              _tuple.update(self.tuple_to_dict(_packet["_source"]))
              for item in _keys:
                _tuple.update(self.tuple_to_dict(_tuple[item]))
              #print(_tuple)
#              _tuple.update(self.tuple_to_dict(_tuple["layers"]))
#              print(_tuple["diameter"])
#              _tuple.update(self.tuple_to_dict(_tuple["diameter"]))
              #print(_tuple["diameter"])
              for item in _tuple["diameter"]:
                if item[0] == "diameter.avp":
                  #print(item[1])
                  avp.append(item)
                elif item[0] == "diameter.avp_tree":
                  avp_code.append(item[1][0])
                  for sub_item in item[1]:
                    #print(sub_item)
                    if sub_item[0] == "diameter.Vendor-Specific-Application-Id_tree":
                      for second_sub_item in sub_item[1]:
                        if second_sub_item[0] == "diameter.avp":
                          #print(second_sub_item[1])
                          avp.append(second_sub_item)
                        elif second_sub_item[0] == "diameter.avp_tree":
                          avp_code.append(second_sub_item[1][0])
#                      avp.append(sub_item[1][0])
#                      avp_code.append(sub_item[1][1][1][0])


#              for item in _tuple["diameter.avp_tree"]:
#                if item[0] == "diameter.avp":
#                  print(item[1])
#                  avp.append(item[1])               
#                elif item[0] == "diameter.avp_tree":
#                  avp_code.append(item[1][0])


#                  for sub_item in item[1]:
#                    if sub_item[0] == "diameter.Vendor-Specific-Application-Id_tree":
#                      print(sub_item[1][0])
#                      avp.append(sub_item[1][0])
#                      avp_code.append(sub_item[1][1][1][0])


              #_tuple["_source"]["layers"].update(self.tuple_to_dict(_tuple["_source"]["layers"]["diameter"]))
#              print(type(_tuple))
#              print(type(_tuple["_source"]))
#              print(type(_tuple["_source"]["layers"]))
#              print(type(_tuple["_source"]["layers"]["diameter"]))
#              for key, value in _tuple.items():
#                if key == "_source":
#                  value = dict(json.loads(json.dumps(value, indent = 4)))
#                  _tuple[key] = value
#              for key, value in _tuple["_source"].items():
#                if key == "layers":
#                  value = dict(json.loads(json.dumps(value, indent = 4)))
#                  _tuple["_source"][key] = value
#              for header in _tuple["_source"]["layers"]:
#                if header == "diameter":
#                 1


#              for header in _tuple["diameter"]: #_tuple["_source"]["layers"]["diameter"]:
#                if header[0] == "diameter.avp":
#                  avp.append(header) #_tuple["_source"]["layers"]["diameter"]["diameter.avp"]
#                elif header[0] == "diameter.avp_tree":
#                  for sub_header in header[1]:
#                    if sub_header[0] == "diameter.Vendor-Specific-Application-Id_tree":
#                        for second_sub_header in sub_header[1]:
#                          if second_sub_header[0] == "diameter.avp":
#                            avp.append(second_sub_header)
#                          elif second_sub_header[0] == "diameter.avp.code":
#                            avp_code.append(second_sub_header)
                        #_tuple.update(self.tuple_to_dict(_tuple["diameter.Vendor-Specific-Application-Id_tree"]))
                        #print(_tuple["diameter.Vendor-Specific-Application-Id_tree"])
                        #print(sub_header)
#                    if sub_header[0] == "diameter.avp.code": #print(sub_header[1])
#                        avp_code.append(sub_header) #_tuple["_source"]["layers"]["diameter"]["diameter.avp_tree"]["diameter.avp.code"]



#                        elif sub_header[0] == 'diameter.Vendor-Specific-Application-Id_tree':
#                             
#                          for key, value in _tuple["_source"]["layers"]["diameter"]:
#                            if key == "diameter.avp_tree":
#                              value = dict(json.loads(json.dumps(value, indent = 4)))
#                              _tuple["diameter"][key] = value 
#                             
#
#                          for header in _tuple["_source"]["layers"]["diameter"]["diameter.avp_tree"]["diameter.Vendor-Specific-Application-Id_tree"]:
#                            if header[0] == "diameter.avp":
#                              avp.append(header)
#                            elif header[0] == "diameter.avp_tree":
#                              for sub_header in header[1]:
#                                if sub_header[0] == "diameter.avp.code":
#                                  avp_code.append(sub_header)
                  #print("Packet #{}").format(no)
              for _avp, _avp_code in zip_longest(avp, avp_code):
                if self.ignore_codes == None or (self.ignore_codes and (int(_avp_code[1]) not in self.ignore_codes)):
                  print("AVP CODE: " + str(_avp_code[1]) + ", AVP PAYLOAD: " + str(_avp[1]))
                  message = [str(_avp_code[1]), str(_avp[1])]
                  packet_avps.append(message)
              print(" ")
              res_message.append(packet_avps)
          return res_message 
                
  def differ_avps(self):
#    try:
#      dump1 = self.parsing_avps(self.data1)
#      print("================================================================================================================")
#      dump2 = self.parsing_avps(self.data2)
#      print("================================================================================================================")
#    except ValueError:
#      print("ERROR: BOTH DUMPS SHOULD BE JSONs")
#      sys.exit()

    dump1 = self.parsing_avps(self.data1)
    print("================================================================================================================")
    dump2 = self.parsing_avps(self.data2)
    print("================================================================================================================")

    no = 0
    descs_and_codes = self.parsing_avp_file()
    dict_of_codes = {}
    for item in descs_and_codes:
       dict_of_codes[item[1]] = item[0]
    try:
      for packet1, packet2 in zip_longest(dump1, dump2):
        no += 1
        print(" ")
        print("PACKET #{}".format(no))
        for message1, message2 in zip_longest(packet1, packet2):
          if (message1 is not None) and (message2 is not None):
#            print(message1[0])
#            print(message2[0])
            if int(message1[0]) != int(message2[0]):
              if not any(message2[0] in sublist for sublist in packet1):
                txt = "             AVP CODE: " + message2[0]  + "(" + dict_of_codes[str(message2[0])] + ")" +  ", AVP PAYLOAD: " +  self.decode_avp(message2[1])
                print("  NEW: ")
                print(txt.rstrip())
              if not any(message1[0] in sublist for sublist in packet2):
                txt = "            AVP CODE: " + message1[0]  + "(" + dict_of_codes[str(message1[0])] + ")" +  ", AVP PAYLOAD: " +  self.decode_avp(message1[1])
                print("  DELETED:  ")
                print(txt.rstrip())
              elif not any(message2[1] in sublist for sublist in packet1):
                txt = "  AVP CODE: " + message1[0]  + "(" + dict_of_codes[str(message1[0])] + ")" +  ", AVP PAYLOAD (MODIFIED): " + self.decode_avp(message2[1])
                print(txt.rstrip())
              elif not self.warn:
                 txt = "  AVP CODE: " + message1[0]  + "(" + dict_of_codes[str(message1[0])] + ")" +  ", AVP PAYLOAD: " +  self.decode_avp(message1[1])
                 print(txt.rstrip())
              else:
                pass
            elif not self.warn: #flag --warn
             txt = "  AVP CODE: " + message1[0]  + "(" + dict_of_codes[str(message1[0])] + ")" +  ", AVP PAYLOAD: " +  self.decode_avp(message1[1])
             print(txt.rstrip())
            else:
              pass
          else:
            if message1 is None:
              if any(message2[0] in sublist for sublist in packet1) and not self.warn:
                txt = "  AVP CODE: " + message2[0]  + "(" + dict_of_codes[str(message2[0])] + ")" +  ", AVP PAYLOAD: " +  self.decode_avp(message2[1])
                print(txt.rstrip())
              elif not self.warn:
                txt = "             AVP CODE: " + message2[0]  + "(" + dict_of_codes[str(message2[0])] + ")" +  ", AVP PAYLOAD: " +  self.decode_avp(message2[1])
                print("  NEW:  ")
                print(txt.rstrip())
              else:
                pass
            if message2 is None:
              if any(message1[0] in sublist for sublist in packet2) and not self.warn:
                txt = "  AVP CODE: " + message1[0]  + "(" + dict_of_codes[str(message1[0])] + ")" +  ", AVP PAYLOAD: " +  self.decode_avp(message1[1])
                print(txt.rstrip())
              elif not self.warn:
                print("  DELETED:  ")
                txt = "             AVP CODE: " + message1[0] + "(" + dict_of_codes[str(message1[0])] + ")" + ", AVP PAYLOAD: " +  self.decode_avp(message1[1])
                print(txt.rstrip())
              else:
                pass
        print(" ")
    except TypeError as e:
#       traceback.print_exc()
#       print(e)
       print("MISSING PACKETS STARTING FROM THIS ONE")
       print(" ")
       longer_dump = dump1 if len(dump1) > len(dump2) else dump2
       for packet in longer_dump[no-1:]:
         print("MISSING PACKET #{}".format(no))
         no += 1
         for message in packet:
           print("  AVP CODE: " + message[0] + ", AVP PAYLOAD: " +  self.decode_avp(message[1]))


if __name__ == "__main__":
  parser = argparse.ArgumentParser(description="Keys for logging and Diameter codes ignoring")
  parser.add_argument("--warn", action="store_true", help="Inspecting packets only having attributes DELETED/NEW/MODIFIED")
  parser.add_argument("--ignore", nargs='+', type=int, help="Ignore certain Diameter codes if you need to. Define them in a list e.g [268, 272]")
  args = parser.parse_args()
  with open('output.log', 'a') as f:
    original_stdout = sys.stdout
    sys.stdout = Tee(sys.stdout, f)
    merging = Comparison(args)
    merging.parsing_avp_file()
    merging.start_diff()
    merging.differ_avps()
    merging.start_count()
    sys.stdout = original_stdout
    

