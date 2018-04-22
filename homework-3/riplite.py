from distancevector import DistanceVector
import sys


if __name__ == '__main__':
    if len(sys.argv) == 2:
        host = sys.argv[1]
        print(host)
    else:
        print('Error with parameters')
