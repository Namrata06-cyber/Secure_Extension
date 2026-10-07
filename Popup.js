chrome.tabs.query(
    {
        active: true,
        currentWindow: true
    },

    function(tabs) {

        if (!tabs || tabs.length === 0) {
            return;
        }


        const tabId =
            tabs[0].id;


        const tabURL =
            tabs[0].url;


        document.getElementById(
            "url"
        ).textContent =
            tabURL || "Unavailable";


        chrome.storage.local.get(
            [String(tabId)],

            function(result) {

                const data =
                    result[String(tabId)];


                if (!data) {

                    document.getElementById(
                        "risk"
                    ).textContent =
                        "No analysis";


                    document.getElementById(
                        "level"
                    ).textContent =
                        "Refresh the webpage and try again.";


                    return;
                }


                // Overall score

                document.getElementById(
                    "risk"
                ).textContent =
                    data.finalScore + "/100";


                // Risk level

                document.getElementById(
                    "level"
                ).textContent =
                    data.level;


                // URL score

                document.getElementById(
                    "urlScore"
                ).textContent =
                    "Risk Score: " +
                    data.urlScore +
                    "/100";


                // URL warnings

                const urlList =
                    document.getElementById(
                        "urlWarnings"
                    );


                if (data.urlWarnings.length === 0) {

                    const li =
                        document.createElement("li");

                    li.textContent =
                        "No suspicious URL patterns detected.";

                    urlList.appendChild(li);

                } else {

                    data.urlWarnings.forEach(
                        warning => {

                            const li =
                                document.createElement("li");

                            li.textContent =
                                warning;

                            urlList.appendChild(li);
                        }
                    );
                }


                // JavaScript score

                document.getElementById(
                    "jsScore"
                ).textContent =
                    "Risk Score: " +
                    data.jsScore +
                    "/100";


                // JavaScript warnings

                const jsList =
                    document.getElementById(
                        "jsWarnings"
                    );


                if (data.jsWarnings.length === 0) {

                    const li =
                        document.createElement("li");

                    li.textContent =
                        "No suspicious JavaScript patterns detected.";

                    jsList.appendChild(li);

                } else {

                    data.jsWarnings.forEach(
                        warning => {

                            const li =
                                document.createElement("li");

                            li.textContent =
                                warning;

                            jsList.appendChild(li);
                        }
                    );
                }

            }
        );

    }
);
