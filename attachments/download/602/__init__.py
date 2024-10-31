"""A basic inventory plugin""" 
from pkg_resources import resource_filename
from prewikka import database, env, utils, view
from inventory import templates

class Inventory(view.View):
    """The main Inventory view""" 
    plugin_name = "Inventory" 
    plugin_description = "A basic inventory plugin" 
    plugin_version = "1.0.0" 
    view_name = "Inventory" 
    view_section = "Inventory"
    plugin_database_version = "0"
    view_template = templates.inventory
    view_parameters = InventoryParameters
    plugin_htdocs = (("inventory", resource_filename(__name__, "htdocs")),)

    def __init__(self):
        view.View.__init__(self)
        self._config = getattr(env.config, "inventory", {})
        self._db = InventoryDatabase() 
        env.hookmgr.declare_once("HOOK_LINK")
        env.hookmgr.register("HOOK_LINK", self._get_inventory_link)
          
    def _get_inventory_link(self, value):
        """Create a link to the inventory to be displayed in the alert view""" 
        return ("host",
                "Search in inventory",
                utils.create_link(self.view_path, {"search": value}),
                False)

    def render(self):
        params = self.parameters
        if "hostname" in params:
            self._db.add_host(params.get("hostname"),
                              params.get("address"),
                              params.get("os"))
        self.dataset["inventory"] = self._db.get_hosts(params.get("search"))
        self.dataset["title"] = self._config.get("title", "Inventory")     

class InventoryDatabase(database.DatabaseHelper):
    """Handle database queries related to the inventory""" 

    def get_hosts(self, keyword=None):
        """Return all hosts in the inventory database matching the keyword""" 
        query = "SELECT hostname, address, os FROM Prewikka_Inventory" 
        if keyword:
            query += (" WHERE hostname = %(keyword)s" 
                      " OR address = %(keyword)s" 
                      " OR os = %(keyword)s" %
                      {"keyword": self.escape(keyword)})
        return self.query(query)

    def add_host(self, hostname, address, os):
        """Add a host to the inventory database""" 
        self.query("INSERT INTO Prewikka_Inventory (hostname, address, os) " 
                   "VALUES (%s, %s, %s)" % (self.escape(hostname),
                                            self.escape(address),
                                            self.escape(os)))
