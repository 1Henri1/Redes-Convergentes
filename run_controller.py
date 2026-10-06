from os_ken.base import app_manager

app_mgr = app_manager.AppManager.get_instance()
app_mgr.run_apps(["controller"])