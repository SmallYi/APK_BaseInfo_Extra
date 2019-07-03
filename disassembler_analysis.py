#!/usr/bin/env python
#-*- coding: utf-8 -*-
import sys
import os
from androguard.core.bytecodes import dvm,apk
from androguard.core.analysis import analysis

class APK_Analysis():
    def __init__(self):
        pass

    def getdex(self,path):
        a = apk.APK(path)
        apk_dex = a.get_dex()
        apk_name = a.get_app_name()
        apk_flag = a.is_valid_APK()
        return apk_dex,apk_name,apk_flag

    def eachFile(self,filepath):
        child=[]
        pathDir =  os.listdir(filepath)
        for allDir in pathDir:
            child.append(os.path.join('%s%s' % (filepath, allDir)))
        return child 

    def eachfile(self,m,dirname):
        ii=0
        for root,dirs,files in os.walk(dirname):
            for f in files:
                if f.endswith('.apk'):
                    ii=ii+1
                    if(ii>=m):
                        yield os.path.join(root,f)

    def get_graph(self,gg):
        list_edge={}
        for i in gg.get_basic_blocks().get():
            for j in i.get_next():
                list_edge.setdefault(i,[]).append(j[2])
        return list_edge

    def find_all_paths(self,graph, start, end, path=[]):
        path = path + [start]
        if start == end:
            return [path]
        if not graph.has_key(start):
            return []
        paths = []
        for node in graph[start]:
            if node not in path:
                newpaths = self.find_all_paths(graph, node, end, path)
                for newpath in newpaths:
                    paths.append(newpath)
        return paths     

    def has_cycle(self,g):
        where_from = dict()
        visited = set()
        stack = dict()
        cycle = []
        def dfs(n):
            visited.add(n)
            stack[n] = True
            for x in g.get(n,[]):
                if x not in visited:
                    where_from[x] = n
                    dfs(x)
                elif stack.get(x,False):
                    cycle_path = self.get_path(where_from,x,n)
                    if cycle_path:
                        cycle.append(cycle_path+[x])
            stack[n] = False

        for x in g:
            if x not in visited:
                dfs(x)
        return cycle

    def get_path(self,where_from,_from,to):
        try:
            path = []
            x = to
            while x != _from:
                path.insert(0,x)
                x = where_from[x]
            path.insert(0,x)
            return path
        except:
            return []


    def find_nodes(self,root,S=None):
        if S is None:
            S=set()
        S.add(root)
        if root.get_next():
           for j in root.get_next():
               nextnode=j[2]
               if nextnode in S: 
                   continue
               self.find_nodes(nextnode,S)  
        return (len(S)-1)

    def Sum(self,root):
        if not root:
            return 0
        else:
            if root.get_next():
                rn=root.get_next()
                return 1+self.Sum(rn[2])

    def find_path(self,start,end,path=[]):
        path=path+[start]
        if start==end:
            return path
        if not start:
            return None
        for node in start.get_next():
            nextnode=node[2]
            if nextnode not in path:
                newpath=self.find_path(nextnode,end,path)
                if newpath:
                    return newpath
        return None
            
    def find_loop(self,gg,root):
        loop_num=0
        if root.get_next():
            start=root.get_next()
            if root.get_prev():
                end=root.get_prev()
                for j in start:
                    for k in end:
                        pathh=self.find_all_paths(gg,j[2],k[2],path=[])
                        if pathh:
                            loop_num=loop_num+len(pathh)
        return loop_num

    def find_loops(self,gg,i):
        loop_num=0
        cycle=self.has_cycle(gg)
        for j in cycle:
            if j:
                for k in j:
                    if k==i:
                        loop_num=loop_num+1
        return loop_num
            
    def getfile(self,filename):
        filee = open(filename,'a')
        return filee

    def save_base_feature(self,filehandle,classname,funcname,data):
        if len(data):
            filehandle.write('%s' % classname)
            filehandle.write('%s#' % funcname)
            filehandle.write('%s\n' % data)
        else:
            print(classname,funcname,'#NoData')

    def AnalysisStart(self,filepath,savefolder):
        apk_dex,apk_name,apk_flag = self.getdex(filepath)
        d = dvm.DalvikVMFormat(apk_dex)
        x = analysis.Analysis(d)

        #判断APK是否有效
        if apk_flag:
            pass
        else:
            deal_msg = 'not valid'
            return apk_name,deal_msg

        # 创建保存的文件夹
        path = savefolder + filepath.split('/')[-1].split('.')[0] + '/'
        if not os.path.exists(path):
            os.makedirs(path)
            print(path,'create success')
        else:
            deal_msg = path + ' already exist'
            return apk_name,deal_msg

        base_source = path + apk_name + '_base_source.txt'
        bs_file = open(base_source,'w')

        for method in d.get_methods():
            g = x.get_method(method)
            if method.get_code() == None:
                continue
            idx = 0
            graphh=self.get_graph(g)
            self.has_cycle(graphh)
            properity=[]
            index=0
            for i in g.get_basic_blocks().get():
                index=index+1
                node_pro=[]
                child_num=0
                father_num=0
                node_pro.append(index)
                w=self.find_nodes(i)
                loop=self.find_loops(graphh,i)
                node_pro.append(w)
                node_pro.append(loop)
                for j in i.get_next():
                    child_num=child_num+1
                for j in i.get_prev():
                    father_num=father_num+1
                node_pro.append(child_num)
                node_pro.append(father_num)
                ins_len=0
                for ins in i.get_instructions():
                    idx += ins.get_length()
                    ins_len=ins_len+1
                node_pro.append(ins_len)
                properity.append(node_pro)
            self.save_base_feature(bs_file,method.get_class_name(),method.get_name(),properity)
        bs_file.close()
        return apk_name,'analysis success'

           
