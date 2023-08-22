from apscheduler.schedulers.background import BackgroundScheduler

scheduler = BackgroundScheduler()

def start_or_reset_background_refresh():
    if scheduler.get_jobs():
        scheduler.remove_all_jobs()

    scheduler.add_job(func=refresh_token, trigger="interval", minutes=30)
    if not scheduler.running:
        scheduler.start()