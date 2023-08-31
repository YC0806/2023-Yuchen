import re
import numpy as np
import copy
import os


class AuditdRecord:
    def __init__(self) -> None:
        self.type = None
        self.timestamp = None
        self.id = None
        self.data = None

        self.data_dict = None
    
    def decode_txt_record(self,txt_record):
        try:
            # _type = re.search(r'type=(\w*)\s', txt_record).group(1)
            # _timestamp,_id,_data = re.search(r'msg=audit\(([^:]*):([^:]*)\):(.*\n)', txt_record).groups()

            # re expression include UNKNOWN[1333]
            _type,_timestamp,_id,_data = re.search(r'type=([^\s]*)\smsg=audit\(([^:]*):([^:]*)\):\s(.*\n)', txt_record).groups()


            # phrase the data string
            data_dict = {}
            for key,val in re.findall(r'(\w+)\s*=\s*(.*?)[\s\n]', _data) :
                data_dict[key] = val
        except:
            print(txt_record)
            raise

        self.type = _type
        self.timestamp = _timestamp
        self.id = _id
        self.data = _data

        self.data_dict = data_dict


class AuditdNode():
    def __init__(self, nodetype, arg_dict,timestamp) -> None:
        self.nodetype = nodetype
        self.arg_dict = arg_dict
        self.timestamp = timestamp
        self.feature = None

    def feature_extract(self):
        features = []
        features.append(self.nodetype)

        return features
        
    def __str__(self) -> str:
        text = f"{self.nodetype} {self.timestamp} "
        for key in self.arg_dict.keys():
            text += f"{key}:{self.arg_dict[key]} "

        return text

    def __eq__(self, __value: object) -> bool:
        if self.nodetype == __value.nodetype:
            flag_eq = True
            for key in self.arg_dict.keys():
                if key not in __value.arg_dict.keys():
                    flag_eq = False
                    break
                elif self.arg_dict[key] != __value.arg_dict[key]:
                    flag_eq = False
                    break
            return flag_eq
        else:
            return False
    
    def __ne__(self, __value: object) -> bool:
        if self.__eq__(__value):
            return False
        else:
            return True
            

class AuditdEdge():
    def __init__(self, i_a, i_b, edgetype, arg_dict,timestamp) -> None:
        self.i_a = i_a
        self.i_b = i_b
        self.edgetype = edgetype
        self.arg_dict = arg_dict
        self.timestamp = timestamp
    
    def feature_extract(self):
        features = []
        if "syscall" not in self.arg_dict:
            raise AttributeError
        else:
            features.append(self.arg_dict['syscall'])

        return features

    def __str__(self) -> str:
        text = f"{self.i_a} {self.i_b} "
        for key in self.arg_dict.keys():
            text += f"{key}:{self.arg_dict[key]} "
        
        return text

    def __eq__(self, __value: object) -> bool:
        if self.i_a == __value.i_a and self.i_b == __value.i_b and self.edgetype == __value.edgetype:
            flag_eq = True
            for key in self.arg_dict.keys():
                if key not in __value.arg_dict.keys():
                    flag_eq = False
                    break
                elif self.arg_dict[key] != __value.arg_dict[key]:
                    flag_eq = False
                    break
            return flag_eq
        else:
            return False
    
    def __ne__(self, __value: object) -> bool:
        if self.__eq__(__value):
            return False
        else:
            return True
        

class AuditdEvent:
    def __init__(self, id) -> None:
        self.id = id
        self.records = []
        self.node_list = []
        self.edge_list = []

    def get_timestamp(self,method='min'):
        timestamps = []
        for _record in self.records:
            timestamps.append(float(_record.timestamp))
        if method == 'min':
            return min(timestamps)
        elif method == 'max':
            return max(timestamps)
        else:
            raise AttributeError
    
    # Indentification
    def event_analyse(self):
        self.node_list = []
        self.edge_list = []

        def _add_node(nodetype, arg_dict, timestamp):
            # Duplicate check
            newnode = AuditdNode(nodetype,arg_dict,timestamp)
            for i_node, _node in enumerate(self.node_list):
                if _node == newnode:   
                    return i_node
        
            self.node_list.append(newnode)

            return len(self.node_list)-1

        def _add_edge(i_a,i_b,edgetype,arg_dict,timestamp): 
            # Duplicate check
            newedge = AuditdEdge(i_a,i_b,edgetype,arg_dict,timestamp)
            for i_edge, _edge in enumerate(self.edge_list):
                if _edge == newedge:
                    return i_edge
                     
            self.edge_list.append(newedge)

            return len(self.edge_list)-1

        i_process = None
        i_parentprocess = None
        i_user = None
        i_exe = None

        _ts = self.get_timestamp()

        for _record in self.records:
            _type = _record.type
            _keys = _record.data_dict.keys()
            _data_dict = _record.data_dict
            
            # Process
            if _type == "SYSCALL":
                _pid = _data_dict['pid']
                _ppid = _data_dict['ppid']
                _uid = _data_dict['uid']
                _exe = _data_dict['exe']
                _syscall = _data_dict['syscall']

                # Create Nodes
                i_process = _add_node(nodetype='Process',arg_dict={"pid":_pid},timestamp=_ts)
                i_parentprocess = _add_node(nodetype='Process',arg_dict={"pid":_ppid},timestamp=_ts)
                i_user = _add_node(nodetype='User',arg_dict={"uid":_uid},timestamp=_ts)
                i_exe = _add_node(nodetype='Executable',arg_dict={"exe":_exe},timestamp=_ts)

                # Creat Edges
                _add_edge(i_a=i_parentprocess,i_b=i_process, edgetype=None,arg_dict={"syscall":_syscall},timestamp=_ts)
                _add_edge(i_a=i_user,i_b=i_process, edgetype=None,arg_dict={"syscall":_syscall},timestamp=_ts)
                _add_edge(i_a=i_exe,i_b=i_process, edgetype=None,arg_dict={"syscall":_syscall},timestamp=_ts)


        
        if i_process is None:
            return None
        # Resources 
        for _record in self.records:
            try:
                _type = _record.type
                _keys = _record.data_dict.keys()
                _data_dict = _record.data_dict
                
                if _type == "EXECVE":
                    for i_arg in range(int(_data_dict['argc'])):
                        _arg = _data_dict[f'a{i_arg}']
                        if len(_arg) == 0:
                            continue
                        # Process arguments
                        if _arg[0] == "\"" and _arg[-1] == "\"":
                            _arg = _arg[1:-1]

                        if len(_arg) == 0:
                            continue
                        
                        if _arg[0] == "/":
                            i_file = _add_node(nodetype="File",arg_dict={"path":_arg}, timestamp=_ts)
                            _add_edge(i_a=i_process,i_b=i_file,edgetype=None,arg_dict={"syscall":_syscall},timestamp=_ts)
                        
                
                # Socket
                if _type == "SOCKADDR":
                    _saddr = _data_dict['saddr']

                    i_socket = _add_node(nodetype="Socket",arg_dict={"saddr":_saddr}, timestamp=_ts)
                    _add_edge(i_a=i_process,i_b=i_socket,edgetype=None,arg_dict={"syscall":_syscall},timestamp=_ts)


                # File
                if _type == "PATH":
                    _path = _data_dict['name']

                    i_file = _add_node(nodetype="File",arg_dict={"path":_path}, timestamp=_ts)
                    _add_edge(i_a=i_process,i_b=i_file,edgetype=None,arg_dict={"syscall":_syscall},timestamp=_ts)
                
                if _type == "CWD":
                    _path = _data_dict['cwd']

                    i_file = _add_node(nodetype="File",arg_dict={"path":_path}, timestamp=_ts)
                    _add_edge(i_a=i_process,i_b=i_file,edgetype=None,arg_dict={"syscall":_syscall},timestamp=_ts)
            except:
                print(_record.data)
                raise
            # Other USer
            # elif 'uid' in _keys:
            #     __uid = _data_dict['uid']
            #     if _type != "ANOM_PROMISCUOUS":
            #         __pid = _data_dict['pid']

    def __str__(self) -> str:
        text = ""
        for _record in self.records:
            text += f"{_record.type} {_record.data}"
            
        return text

def _read_log(log_file_path):
    # f = open(r"..\Data\2021-09-11-umbrella-experiment-32run-fran\2021-09-10T185854\2021-09-10T191416_audit.log",'r')
    f = open(log_file_path,'r')
    raw_auditd_record_list = f.readlines()
    # raw_log_data = f.read()
    # print(raw_log_data)
    f.close()
    
    auditd_record_list = []
    for row in raw_auditd_record_list:
        record = AuditdRecord()
        record.decode_txt_record(row)
        auditd_record_list.append(record)
        # print(f"{record.type} {record.timestamp} {record.id} {len(record.data_dict.keys())}")
    
    return auditd_record_list

def read_log(log_file_path):
    return _read_log(log_file_path=log_file_path)

def log2graph(input_path, interval=60, overlap=30):
    auditd_record_list = _read_log(input_path)
    if len(auditd_record_list) == 0:
        return None
    
    audit_event_dict = {}
    for _record in auditd_record_list:
        if _record.id in audit_event_dict:
            _event = audit_event_dict[_record.id]
        else:
            _event = AuditdEvent(id=_record.id)
            audit_event_dict[_record.id] = _event
        _event.records.append(_record)

    for _event in audit_event_dict.values():
        _event.event_analyse()
    
    # Sort the event by timestamp
    event_list = list(audit_event_dict.values())
    event_list.sort(key=lambda x:x.get_timestamp())
    
    # Given timestamp range return node_list and edge_list
    # The node and edge in list has sorted by timestamp

    _interval = interval
    _overlap = overlap

    graph_nodes_list = []
    graph_edges_list = []
    graph_timestamp_list = []

    _start = event_list[0].get_timestamp()
    _end = event_list[-1].get_timestamp()

    base = _start
    i_event = 0
    i_event_overlap = None

    while base <= _end:
        _node_list = []
        _edge_list = []

        
        while i_event < len(event_list) and event_list[i_event].get_timestamp() < base+_interval:
            if event_list[i_event].get_timestamp() >= base+_interval-_overlap:
                i_event_overlap = i_event

            _event = event_list[i_event]

            event_node_list = copy.deepcopy(_event.node_list)
            event_edge_list = copy.deepcopy(_event.edge_list)
            
            for _edge in event_edge_list:
                _edge.i_a += len(_node_list)
                _edge.i_b += len(_node_list)

            _node_list += event_node_list
            _edge_list += event_edge_list
            
            i_event += 1
        
        # for _node in _node_list:
        #     print(_node)
        # print(f"Original Node Number: {len(_node_list)}")  

        # Integrate Node
        _integrate_map = {} # origin index: integrate index
        for i_node in range(len(_node_list)):
            if i_node in _integrate_map:
                continue
            else:
                for j_node in range(i_node+1,len(_node_list)):
                    if j_node in _integrate_map:
                        continue
                    else:
                        _node_i = _node_list[i_node]
                        _node_j = _node_list[j_node]
                        if _node_i == _node_j:
                            _integrate_map.update({j_node: i_node})

        _node_index = list(range(len(_node_list)))
        for i_node in sorted(list(_integrate_map.keys()),reverse=True):
            _node_list.pop(i_node)
            _node_index.pop(i_node)
        # print(_node_index)
        _index_map = dict(zip(_node_index,range(len(_node_index))))
        # print(_integrate_map)
        for i_edge in range(len(_edge_list)):
            _edge = _edge_list[i_edge]
            if _edge.i_a in _integrate_map:
                _edge.i_a = _integrate_map[_edge.i_a]
            if _edge.i_b in _integrate_map:
                _edge.i_b = _integrate_map[_edge.i_b]
            
            _edge.i_a = _index_map[_edge.i_a]
            _edge.i_b = _index_map[_edge.i_b]

        # for _node in node_list:
        #     print(_node)
        # print(f"Integrated Node Number: {len(_node_list)}")    
        # print(f"Edge Number: {len(_edge_list)}")

        #TODO Integrate Edge

        if len(_node_list) != 0:
            graph_nodes_list.append(_node_list)
            graph_edges_list.append(_edge_list)
            graph_timestamp_list.append(base)

        base = base+_interval-_overlap
        if i_event_overlap is not None:
            i_event = i_event_overlap
    
    graph_timestamp_array = np.array(graph_timestamp_list)
    # print('graph_timestamp_array',graph_timestamp_array.shape)
    # Register the node to a gobal list for hidden state transfer between time slots
    global_node_list = []
    graph_node_indices_list = []
    num_node = []

    for _node_list in graph_nodes_list:
        _node_indices = []
        for _node_i in _node_list:
            flag_register = 0
            for j_node, _node_j in enumerate(global_node_list):
                if _node_i == _node_j:
                    _node_indices.append(j_node)
                    flag_register = 1
                    break
            if flag_register == 0:
                global_node_list.append(_node_i)
                _node_indices.append(len(global_node_list)-1)
        graph_node_indices_list.append(_node_indices)
        num_node.append(len(global_node_list))

    # Node Attr
    node_attr_array = None
    node_attr_list = []
    for _node in global_node_list:
        node_attr_list.append(_node.feature_extract())
    node_attr_array = np.array(node_attr_list)
    # node_attr_encoder = OneHotEncoder(sparse_output=False)
    # node_attr_array = node_attr_encoder.fit_transform(node_attr_list)
    # print('node_attr_array',node_attr_array.shape)


    # Node Index
    node_flag_array = None
    node_index_array = None

    node_flag_list = []
    node_index_list = []
    base = 0
    for i_graph, _node_indices in enumerate(graph_node_indices_list):
        base += len(_node_indices)
        node_flag_list.append(base)
        node_index_list += _node_indices

    node_index_array = np.array(node_index_list)
    node_flag_array = np.array(node_flag_list)

    # print('node_flag_array',node_flag_array.shape)
    # print('node_index_array',node_index_array.shape)

    # Edge
    edge_flag_array = None
    edge_attr_array = None
    edge_index_array = None

    edge_flag_list = []
    edge_attr_list = []
    edge_index_list = []

    base = 0
    for _edge_list in graph_edges_list:
        base += len(_edge_list)
        edge_flag_list.append(base)
        edge_attr_list += [_edge.feature_extract() for _edge in _edge_list]
        edge_index_list += [[_edge.i_a,_edge.i_b] for _edge in _edge_list]

    edge_attr_array = np.array(edge_attr_list)
    # edge_attr_encoder = OneHotEncoder(sparse_output=False)
    # edge_attr_array = edge_attr_encoder.fit_transform(edge_attr_list)
    edge_index_array = np.array(edge_index_list)
    edge_flag_array = np.array(edge_flag_list)

    # print('edge_flag_array',edge_flag_array.shape)
    # print('edge_attr_array',edge_attr_array.shape)
    # print('edge_index_array',edge_index_array.shape)
    
    # np.savez(
    #     f'{output_path}.npz',
    #     node_attr=node_attr_array,
    #     node_flag=node_flag_array,
    #     node_index=node_index_array,
    #     edge_flag=edge_flag_array,
    #     edge_attr=edge_attr_array,
    #     edge_index=edge_index_array,
    #     timestamp=graph_timestamp_array,
    #     )
    return {
        'node_attr': node_attr_array,
        'node_flag': node_flag_array,
        'node_index': node_index_array,
        'edge_flag': edge_flag_array,
        'edge_attr': edge_attr_array,
        'edge_index': edge_index_array,
        'timestamp': graph_timestamp_array,
    }
        