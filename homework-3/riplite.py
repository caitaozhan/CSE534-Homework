from distancevector import DistanceVector
import sys
import socket
from thread import start_new_thread
import time

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
        self.my_dv = DistanceVector(hostname)
        self.neighbor     = []
        self.non_neighbor = []

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


    def __str__(self):
        string = self.hostname + "'s distance vector: \n"
        string += self.my_dv.__str__()
        return string


    def socket_test(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            print('socket successfully created')
        except socket.error as err:
            print('socket creation failed with error %s' %(err))

        port = 80

        try:
            host_ip = socket.gethostbyname('www.google.com')
            print(host_ip)
        except socket.error as err:
            print('there was an error resolving the host')

        s.connect((host_ip, port))
        print("the socket has successfully connected to google")


    def start_listening(self):
        '''This is the server side.
        '''
        host = ''
        port = 6666

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.bind((host, port))
            s.listen(5)
            print(self.hostname + ' is listening at port %d' %(port))
        except socket.error as err:
            print(self.hostname + ' socket failed with error %s' %(err))
        while 1:
            try:
                conn, addr = s.accept() # wait to accept a connection - blocking call
                print('connection with ' + addr[0] + ':' + str(addr[1]))

                start_new_thread(self.clientthread, (conn,))
            except Exception as e:
                print('Oops! Error!. Socket is now closed.')
                s.close()


    def clientthread(self, conn):
        '''Handle connection. Used for creating threads
        '''
        dv = ''
        while 1:
            try:
                data = conn.recv(1024)  # data is the distance vector
                reply = 'OK...'
                if not data:
                    break
                else:
                    dv = data.split('\n')
                    print(data)
            except Exception as e:
                print('error in receiving data', e)

            conn.sendall(self.hostname + ' received your data')
        conn.close()
        print('start updating my DV')
        print(self.my_dv)
        neighbor_dv = []
        for distance in dv[1:-1]:
            distance  = distance.split(' ')
            if distance[2] != '' and distance[0] != self.hostname:
                neighbor = distance[0]
                weight   = distance[1]
                nexthop  = distance[2]
                neighbor_dv.append(DistanceVector.Distance(Dest=neighbor, Cost=int(weight), Next=nexthop))

        neighbor = dv[0]   # receive the distance vector from neighbor
        flag = False       # record whether there is an update
        cost_to_neighbor = 9999
        for distance in self.my_dv.dv:
            if distance.Dest == neighbor:
                cost_to_neighbor = distance.Cost

        print(neighbor_dv)

        my_new_dv = []
        for neighbor_d in neighbor_dv[:]:  # a copy of neighbor_dv
            destination = neighbor_d.Dest
            for mydis in self.my_dv.dv:
                if mydis.Dest == destination:
                    pre_cost = mydis.Cost
                    new_cost = cost_to_neighbor + neighbor_d.Cost
                    print(pre_cost, new_cost)
                    if new_cost < pre_cost:   # find a new path with lower cost!
                        self.my_dv.dv.remove(mydis)
                        my_new_dv.append(DistanceVector.Distance(Dest=destination, Cost=new_cost, Next=neighbor))
                        flag = True
        if flag:
            for new_d in my_new_dv:
                self.my_dv.dv.append(new_d)


        print('end updating my DV')
        print(self.my_dv)


    def send_dv(self):
        '''Send host's distance vector to all its neighbors
        '''
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        port = 6666
        ip = 'localhost'
        try:
            s.connect((ip, port))
            s.send(self.data_to_send())
            reply = s.recv(1048)
            print(reply)
        except socket.error as err:
            print('Oops! error when sending distance vector', err)
        finally:
            s.close()


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
        if hostname == 'h1':
            host.start_listening()
        elif hostname == 'r1':
            host.send_dv()

        '''
        host.start_listening()
        while 1:
            time.sleep(1)
            host.send_dv()
        '''
    else:
        print('Error with parameters')

