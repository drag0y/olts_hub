def showlogs(logfile):
    logs = []
    with open(logfile, 'r') as f:
        for l in f:
            logs.append(l)
    logs = list(reversed(logs))
    return logs