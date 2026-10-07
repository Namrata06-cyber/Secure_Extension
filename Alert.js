function showAlert(result) {

    if (result.level !== "HIGH RISK") {
        return;
    }


    const warningBox =
        document.createElement("div");


    warningBox.id =
        "phishing-detector-warning";


    warningBox.innerHTML = `
        <strong>⚠️ Phishing Warning</strong>
        <br>
        This website may be suspicious.
        <br>
        Risk Score: ${result.score}/100
    `;


    warningBox.style.position = "fixed";

    warningBox.style.top = "20px";

    warningBox.style.left = "50%";

    warningBox.style.transform =
        "translateX(-50%)";

    warningBox.style.background =
        "#d32f2f";

    warningBox.style.color =
        "white";

    warningBox.style.padding =
        "15px 20px";

    warningBox.style.borderRadius =
        "8px";

    warningBox.style.zIndex =
        "999999";

    warningBox.style.fontFamily =
        "Arial, sans-serif";

    warningBox.style.fontSize =
        "15px";

    warningBox.style.boxShadow =
        "0 4px 12px rgba(0,0,0,0.3)";


    document.body.appendChild(
        warningBox
    );


    setTimeout(() => {

        if (warningBox) {
            warningBox.remove();
        }

    }, 7000);
}
