#include <libprelude/prelude.h>


#define ANALYZER_NAME "simple-analyzer"

static int 
add_idmef_object(idmef_message_t *message, const char *object, const char *value)
{
        int ret;
        idmef_value_t *val;
        idmef_path_t *path;
        
        ret = idmef_path_new_fast(&path, object);
        if ( ret < 0 )
                return -1;

        ret = idmef_value_new_from_path(&val, path, value);
        if ( ret < 0 ) {
                idmef_path_destroy(path);
                return -1;
        }

        ret = idmef_path_set(path, message, val);

        idmef_value_destroy(val);
        idmef_path_destroy(path);
        
        return ret;
}


int main(int argc, char **argv)
{ 
	int ret;

	prelude_client_t *client;
	idmef_message_t *idmef;

	/* Prelude init */
	ret = prelude_init(&argc, argv);
	if ( ret < 0 ) {
		prelude_perror(ret, "unable to initialize the prelude library");
		return -1;
	}
        
	ret = prelude_client_new(&client, ANALYZER_NAME);
	if ( ! client ) {
		prelude_perror(ret, "Unable to create a prelude client object");
		return -1;
	}
	
	ret = prelude_client_start(client);
	if ( ret < 0 ) {
		prelude_perror(ret, "Unable to start prelude client");
		return -1;
	}

	/* Idmef init */
	ret = idmef_message_new(&idmef);
	if ( ret < 0 )
		return -1;

	/* Idmef stuff */
	add_idmef_object(idmef, "alert.classification.reference(0).name", "PRELID-1234");
	add_idmef_object(idmef, "alert.classification.reference(0).origin", "PRELID");
	add_idmef_object(idmef, "alert.classification.reference(0).url", "http://www.prelude-ids.org/");
        add_idmef_object(idmef, "alert.assessment.impact.description", "As you can see, this description is useless, because it is describing an event that isn't one!");
        add_idmef_object(idmef, "alert.assessment.impact.severity", "info");
        add_idmef_object(idmef, "alert.assessment.impact.completion", "succeeded");
        add_idmef_object(idmef, "alert.classification.text", "This alert was sent from the simplest analyzer ever");

        add_idmef_object(idmef, "alert.additional_data(0).type", "string");
        add_idmef_object(idmef, "alert.additional_data(0).meaning", "Signature ID");
        add_idmef_object(idmef, "alert.additional_data(0).data", "1");

	prelude_client_send_idmef(client, idmef);
	idmef_message_destroy(idmef);

	prelude_client_destroy(client, PRELUDE_CLIENT_EXIT_STATUS_SUCCESS);

	return 0;
}
