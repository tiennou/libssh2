
#include <stdio.h>


static FILE *summary;

int clar_summary_close_tag(const char *tag, int indent)
{
	const char *indt;

	if (indent == 0) indt = "";
	else if (indent == 1) indt = "\t";
	else indt = "\t\t";

	return fprintf(summary, "%s</%s>\n", indt, tag);
}

int clar_summary_testsuites(const char *idn)
{
	return fprintf(summary, "<testsuites id=\"%s\">\n", idn);
}

int clar_summary_testsuite(const char *name, int test_count, int fail_count, int error_count)
{
	return fprintf(summary, "\t<testsuite name=\"%s\" tests=\"%d\" failures=\"%d\" errors=\"%d\">\n", name, test_count, fail_count, error_count);
}

int clar_summary_testcase(const char *name, const char *classname)
{
	return fprintf(summary, "\t\t<testcase name=\"%s\" classname=\"%s\">\n", name, classname);
}

int clar_summary_failure(const char *type, const char *message, const char *desc)
{
	return fprintf(summary, "\t\t\t<failure type=\"%s\"><![CDATA[%s\n%s]]></failure>\n", type, message, desc);
}

void clar_summary_write(void)
{
	summary = fopen("summary.xml", "w");
	if (!summary) {
		printf("failed to open summary.xml for writing\n");
		return;
	}

	clar_summary_testsuites("id");

	struct clar_report *report = _clar.reports;
	const char *last_suite = NULL;
	while (report != NULL) {
		struct clar_error *error = report->errors;

		if (last_suite == NULL || strcmp(last_suite, report->suite) != 0)
			clar_summary_testsuite(report->suite, 0, 0, 0);

		last_suite = report->suite;

		clar_summary_testcase(report->test, "what");

		while (error != NULL) {
			clar_summary_failure("assert", error->error_msg, error->description);
			error = error->next;
		}

		clar_summary_close_tag("testcase", 2);

		report = report->next;

		if (!report || strcmp(last_suite, report->suite) != 0)
			clar_summary_close_tag("testsuite", 1);
	}

	clar_summary_close_tag("testsuites", 0);

	fclose(summary);
}
