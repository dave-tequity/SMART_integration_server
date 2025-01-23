const url = 'https://fhir.epic.com/interconnect-fhir-oauth/api/FHIR/R4/';
const audencoded= 'https%3A%2F%2Ffhir.epic.com%2Finterconnect-fhir-oauth%2Fapi%2FFHIR%2FR4'
const redirectencoded= 'http%3A%2F%2F127.0.0.1%3A5000%2Flaunch%2Fredirect'


function FHIRDataRetrieved(){
    // console.log(JSON.parse(this.responseText));
    $('.json-viewer').jsonViewer(JSON.parse(this.responseText));

    // $(".resourceviewer-text").text(this.responseText);
}
