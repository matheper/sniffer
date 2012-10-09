from pycap import capture

cap = capture.capture('eth0')
for i in range(100):
    print cap.next()
