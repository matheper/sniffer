from pycap import capture

cap = capture.capture('wlan0')
while True:
    aa = cap.next()
    try:
        if aa[1].version == 6:
            print aa[1].version
            import ipdb; ipdb.set_trace()
    except:
        pass
