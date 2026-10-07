console.log("AccessGuard loaded successfully.");

setTimeout(function () {

    const alerts = document.querySelectorAll(".alert");

    alerts.forEach(function(alert) {

        setTimeout(function() {
            alert.style.opacity = "0";
        }, 4000);

    });

}, 100);