import os
import sys
root = os.path.dirname(os.path.abspath(__file__))
exploit = os.path.join(os.path.dirname(root), "exploit")
if exploit not in sys.path:
    sys.path.insert(0, exploit)
