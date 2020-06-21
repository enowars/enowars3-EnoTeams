function logo_upload() {
    var file = document.getElementById("team_logo").files[0];

    document.getElementById("team_logo").value = "";

    if (typeof file === "undefined") {
        document.getElementById("logo_err").classList.remove("hidden")
        document.getElementById("logo_err").innerHTML = '<span class="msg-type">Error:</span> No image selected'
        return
    }

    if (file.size > (500 * 1024)) {
        document.getElementById("logo_err").classList.remove("hidden")
        document.getElementById("logo_err").innerHTML = '<span class="msg-type">Error:</span> Image exceeds 500kB'
        return
    }

    if (!(file.name.endsWith(".jpg") || file.name.endsWith(".jpeg") ||
            file.name.endsWith(".gif") || file.name.endsWith(".png"))) {
        document.getElementById("logo_err").classList.remove("hidden")
        document.getElementById("logo_err").innerHTML = '<span class="msg-type">Error:</span> Only .jp(e)g, .gif or .png files are allowed'
        return
    }

    var xhr = new XMLHttpRequest();

    xhr.onreadystatechange = function() {
        if (xhr.readyState == 4) {
            if (xhr.status == 204) {
                window.location.replace(window.location.href) // reload with GET
            } else if (xhr.status == 403) {
                window.location.replace("/login.html")
            } else if (xhr.status == 400) {
                document.getElementById("logo_err").classList.remove("hidden")

                if (xhr.responseText == "") {
                    document.getElementById("logo_err").innerHTML = '<span class="msg-type">Error:</span> Bad Request'
                } else {
                    document.getElementById("logo_err").innerHTML = '<span class="msg-type">Error:</span> ' + xhr.responseText
                }
            }
        }
    };

    xhr.open("POST", "/upload.html", true);
    xhr.send(file);
}
