$('#login-button').click(function () {
    $('#login-button').fadeOut("slow", function () {
        $("#container").fadeIn();
        TweenMax.from("#container", .4, {scale: 0, ease: Sine.easeInOut});
        TweenMax.to("#container", .4, {scale: 1, ease: Sine.easeInOut});
    });
});

$(".close-btn").click(function () {
    TweenMax.from("#container", .4, {scale: 1, ease: Sine.easeInOut});
    TweenMax.to("#container", .4, {left: "0px", scale: 0, ease: Sine.easeInOut});
    $("#container, #forgotten-container").fadeOut(800, function () {
        $("#login-button").fadeIn(800);
    });
});

$(".loginBtn").click(() => {
    var username = $("#username").val()
    var password = $("#password").val()
    var data = {username, password}

    console.log(data)
    axios.post("submitLogin",data).then(res => {
        console.log(res)
        if ("success" === res.data)
            location.href = "index.html";
        else {
            $("#loginForm")[0].reset();
            $("input[name=username]").focus();
        }
    })
})