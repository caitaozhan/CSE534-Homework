from distancevector import DistanceVector
import sys
import socket
from thread import start_new_thread
import time
import threading


class Host:
    '''
        This class encapsulate a host (host + router)
    Attr:
        hostname (str)
        my_dv    (DistanceVector): this node's DistanceVector
    '''

    all_hosts = ['h1', 'h2', 'r1', 'r2', 'r3', 'r4']


    def __init__(self, hostname):
        self.hostname = hostname
        print('init cp-0')
        self.my_dv = DistanceVector(hostname)
        print('init cp-1')
        self.neighbor     = []
        self.non_neighbor = []
        self.neighbor_ip  = {}
        self.read_neighbor_ip()
        print(self.neighbor_ip)

        for host in self.all_hosts:
            for distance in self.my_dv.dv:
                if host == distance.Dest:
                    self.neighbor.append(host)
                    break
                elif host == self.hostname:
                    break
            else: # not a neighbor of this host, also not itself
                self.non_neighbor.append(host)

        for host in self.non_neighbor:
            self.my_dv.add_distance(DistanceVector.Distance(Dest=host, Cost=9999, Next=''))

        self.writelog('initialization at timestamp = ' + str(time.time()) + '\n')
        self.writelog(str(self.my_dv) + '\n')


    def writelog(self, message):
        f = open('/home/log/'+self.hostname, 'a')
        f.write(message)
        f.close()


    def read_neighbor_ip(self):
        with open('/home/neighbor/' + self.hostname + '_neighbor', 'r') as f:
            lines = f.readlines()
            for line in lines:
                line = line.strip().split(' ')
                neighbor = line[0]
                ip = line[1]
                self.neighbor_ip[neighbor] = ip


    def __str__(self):
        string = self.hostname + "'s distance vector: \n"
        string += self.my_dv.__str__()
        return string


    def start_listening(self):
        '''This is the server side.
        '''
        host = '0.0.0.0'      # listening to all interfaces
        port = 6666

        s = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.bind((host, port))
            s.listen(5)
            self.writelog((self.hostname + ' is listening at port %d\n' %(port)))
            self.writelog('timestamp = ' + str(time.time()) + '\n')
        except socket.error as err:
            self.writelog((self.hostname + ' socket failed with error %s\n' %(err)))

        #time.sleep(10)

        while 1:
            try:
                conn, addr = s.accept() # wait to accept a connection - blocking call

                t = threading.Thread(target=self.clientthread, args=(conn, addr))
                t.start()
            except Exception as e:
                self.writelog('Oops! Error!. Socket is now closed.\n')
                s.close()


    def clientthread(self, conn, addr):
        '''Handle a connection from client. Used for creating threads
        '''
        print('connection with ' + addr[0] + ':' + str(addr[1]))

        dv = ''

        try:
            data = conn.recv(1024)  # data is the distance vector
            dv = data.split('\n')
            print(data)
        except Exception as e:
            print('error in receiving data', e)

        neighbor = dv[0]            # receive the distance vector from neighbor
        conn.sendall(self.hostname + ' received ' + neighbor + "'s distance vector")
        self.writelog('\n\n' + self.hostname + ' received ' + 'distance vector from ' + neighbor + '\n')

        conn.close()
        neighbor_dv = []
        for distance in dv[1:-1]:
            distance  = distance.split(' ')
            if distance[2] != '' and distance[0] != self.hostname:
                neighbor = distance[0]
                weight   = distance[1]
                nexthop  = distance[2]
                neighbor_dv.append(DistanceVector.Distance(Dest=neighbor, Cost=int(weight), Next=nexthop))

        neighbor = dv[0]            # receive the distance vector from neighbor
        flag = False       # record whether there is an update
        cost_to_neighbor = 9999
        for distance in self.my_dv.dv:
            if distance.Dest == neighbor:
                cost_to_neighbor = distance.Cost

        print(neighbor_dv)

        lock = threading.Lock()               # prevent multiple threads updating distance vector at the same time
        lock.acquire()
        my_new_dv = []
        for neighbor_d in neighbor_dv:
            destination = neighbor_d.Dest
            for mydis in self.my_dv.dv[:]:    # a copy of my distance vector
                if mydis.Dest == destination:
                    pre_cost = mydis.Cost
                    new_cost = cost_to_neighbor + neighbor_d.Cost
                    print(pre_cost, new_cost)
                    if new_cost < pre_cost:   # find a new path with lower cost!
                        self.my_dv.dv.remove(mydis)
                        my_new_dv.append(DistanceVector.Distance(Dest=destination, Cost=new_cost, Next=neighbor))
                        flag = True
        for new_d in my_new_dv:
            self.my_dv.dv.append(new_d)
        lock.release()

        self.writelog('update my DV at timestamp = ' + str(time.time()) + '\n')
        self.writelog(str(self.my_dv) + '\n')

        if flag:
            t = threading.Thread(target=host.send_dv)
            t.start()


    def send_dv(self):
        '''Send host's distance vector to all its neighbors
        '''
        send_queue = []
        for neighbor in self.neighbor:
            send_queue.append(self.neighbor_ip[neighbor])

        port = 6666
        while len(send_queue) >= 1:
            try:
                ip = send_queue[0]
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect((ip, port))
                s.send(self.data_to_send())
                reply = s.recv(1048)
                #self.writelog(reply + '\n')
                send_queue.pop(0)
                time.sleep(0.01)
            except socket.error as err:
                self.writelog('Oops! error when sending distance vector', err)

        self.writelog(self.hostname + ' successfully send dv to neighbors' + '\n')


    def data_to_send(self):
        '''Generate the data to be sent
        '''
        string = self.hostname + '\n'
        for distance in self.my_dv.dv:
            dest = distance.Dest
            cost = distance.Cost
            nexthop = distance.Next
            string += dest + ' ' + str(cost) + ' ' + nexthop + '\n'
        return string


if __name__ == '__main__':

    if len(sys.argv) == 2:
        hostname = sys.argv[1]
        host = Host(hostname)

        t = threading.Thread(target=host.send_dv)
        t.start()

        host.start_listening()

    else:
        print('Error with parameters')


    '''
    hostname = sys.argv[1]
    host = Host(hostname)
    if hostname == 'r1':
        host.start_listening()
    else:
        host.send_dv()
    '''
