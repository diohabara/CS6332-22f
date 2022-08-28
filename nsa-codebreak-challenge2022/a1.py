import re
from collections import Counter
from datetime import datetime, timedelta

import numpy as np
import pandas as pd

FILE_NAME = "vpn.log"

if __name__ == "__main__":
    df = pd.read_csv(FILE_NAME)
    df = df.drop(columns=["Node", "Active", "Service", "Error", "Port", "Proto"])
    df[["Duration"]] = df[["Duration"]].fillna(value=0)
    df = df.sort_values("Duration")
    print(df)
    usernames = df["Username"]
    counter = Counter(usernames)
    # print(counter)
    potential_attackers = []
    for username, count in counter.items():
        if 1 < count:
            potential_attackers.append(username)
    for pa in potential_attackers:
        user_events = df.loc[df["Username"] == pa]
        total_duration, mean, std = (
            user_events["Duration"].sum(),
            user_events["Duration"].mean(),
            user_events["Duration"].std(),
        )
        # print(user_events)
        # print(f"{total_duration=}, {mean=}, {std=}")
        # print(pa)
        for _, ue in user_events.iterrows():
            prog = re.compile(r"(\d{4})\.(\d{2})\.(\d{2}) (\d{2}):(\d{2}):(\d{2}) EDT")
            date = prog.match(ue["Start Time"])
            duration = ue["Duration"]
            if duration == 0:
                continue
            if not date:
                continue
            year, month, day, hour, minute, second = map(int, date.groups(0))
            start_time = datetime(year, month, day, hour, minute, second)
            end_time = start_time + timedelta(0, duration)
            # print(f"{start_time} ~ {end_time}")
