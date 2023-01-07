let add_to_fav = () => {
    if (($("#from-input").val() in name_stations) && ($("#to-input").val() in name_stations)) {
        $.post("addfav", { station_from: $("#from-input").val(), station_to: $("#to-input").val() })
            .done(function (data) {
                if (data == "ok") {
                    M.toast({ html: 'Маршрут добавлен в избранное' })
                    if ($('#favs_container').length > 0)
                        $('#favs_container').load(document.URL + ' #favs');
                }
                else {
                    M.toast({ html: 'Ошибка!' })
                }
            });
    }
    else {
        M.toast({ html: 'Введите корректные данные' })
    }

}