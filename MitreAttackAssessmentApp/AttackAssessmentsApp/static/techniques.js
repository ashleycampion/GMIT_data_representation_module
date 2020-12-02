function showCreate(){
    document.getElementById('display').style.display = "none"
    document.getElementById('update-button').style.display = "none"
    document.getElementById('create-button').style.display = "block"
    document.getElementById('create-update').style.display = "block"
    document.getElementById('create-title').style.display = "block"
    document.getElementById('update-title').style.display = "none"

}
function showUpdate(thisElem){
    var rowElement = thisElem.parentNode.parentNode;
    attackPattern = readAttackPatternFromRow(rowElement)
    populateForm(attackPattern)

    document.getElementById('display').style.display = "none"
    document.getElementById('update-button').style.display = "block"
    document.getElementById('create-button').style.display = "none"
    document.getElementById('create-update').style.display = "block"
    document.getElementById('create-title').style.display = "none"
    document.getElementById('update-title').style.display = "block"

}
function readAttackPatternFromRow(rowElement){
    attackPattern = {}
    attackPattern.attackID = rowElement.getAttribute("id");
    attackPattern.patternName = rowElement.cells[1].firstChild.textContent
    attackPattern.tactic = rowElement.cells[2].firstChild.textContent
    attackPattern.description = rowElement.cells[3].firstChild.textContent
    attackPattern.assessment = rowElement.cells[4].firstChild.textContent

    return attackPattern
    
}
function populateForm(attackPattern){
    var form = document.getElementById('createUpdateForm')

    
    form.querySelector('input[name="attackID"]').value = attackPattern.attackID
    form.querySelector('input[name="attackID"]').disabled=true
    
    form.querySelector('input[name="patternName"]').value = attackPattern.patternName
    form.querySelector('input[name="tactic"]').value = attackPattern.tactic
    form.querySelector('textarea[name="description"]').value = attackPattern.description
    form.querySelector('input[name="assessment"]').value = attackPattern.assessment      
}
function clearForm() {
        var form = document.getElementById('createUpdateForm')


        form.querySelector('input[name="attackID"]').value = ''
        form.querySelector('input[name="attackID"]').disabled = false

        form.querySelector('input[name="patternName"]').value = ''
        form.querySelector('input[name="tactic"]').value = ''
        form.querySelector('textarea[name="description"]').value = ''
        form.querySelector('input[name="assessment"]').value = ''
    }

function doCreate(){
    console.log("in doCreate")
    attackPattern= getAttackPatternFromForm()
    console.log(attackPattern)
    $.ajax({
        url:"/api/attackPatterns",
        data:JSON.stringify(attackPattern),
        method:"POST",
        dataType:"JSON",
        contentType: "application/json; charset=utf-8",
        success:function(result){
            console.log(result) 
            addAttackPatternToTable(attackPattern)
            showDisplay()
            clearForm()

        },
        error:function(xhr,status,error){
            console.log("error"+error)
        }
    })
   
}
function doUpdate(){
    attackPattern = getAttackPatternFromForm()
    updateServer(attackPattern)
    
}
function updateServer(attackPattern){
   $.ajax({
        url: "/api/"+attackPattern.attackID,
        data: JSON.stringify(attackPattern),
        method: "PUT",
        dataType: "JSON",
        contentType: "application/json; charset=utf-8",
        success: function (result) {
            console.log(result)
            updateTableRow(attackPattern)
            showDisplay()
            clearForm()

        },
        error: function (xhr, status, error) {
            console.log("error" + error)
        }
    })
}
function doDelete(thisElem){
    var tableElement = document.getElementById('attackPatternTable');
    var rowElement = thisElem.parentNode.parentNode;
    var index = rowElement.rowIndex;
    attackID = rowElement.getAttribute("id");
    $.ajax({
        url:"/api/"+attackID,
        method:"DELETE",
        dateType:"JSON",
        success:function(result){
            tableElement.deleteRow(index);
        },
        error:function(xhr,status,error){
            console.log(error)
        }
    })
    
}
function updateTableRow(attackPattern){
    rowElement = document.getElementById(attackPattern.attackID)
    rowElement.cells[1].firstChild.textContent = attackPattern.patternName
    rowElement.cells[2].firstChild.textContent = attackPattern.tactic
    rowElement.cells[3].firstChild.textContent = attackPattern.description
    rowElement.cells[4].firstChild.textContent = attackPattern.assessment
    //console.log("updating table")
}
function getAttackPatternFromForm(){
    var form = document.getElementById('createUpdateForm')

    var attackPattern = {}
    attackPattern.attackID = form.querySelector('input[name="attackID"]').value
    attackPattern.patternName = form.querySelector('input[name="patternName"]').value
    attackPattern.tactic = form.querySelector('input[name="tactic"]').value
    attackPattern.description = form.querySelector('textarea[name="description"]').value
    attackPattern.assessment = form.querySelector('input[name="assessment"]').value
    //console.log(attackPattern)
     return attackPattern
}
 function showDisplay() {
        document.getElementById('display').style.display = "block"
        document.getElementById('create-update').style.display = "none"

    }

function populateTable(){
    //ajax getAll
   $.ajax({
       url:'http://127.0.0.1:5000/api/attackPatterns',
       method:'GET',
       datatype:'JSON',
       success:function(results){
            if (document.title.split(": ")[1] == "all") {
            for (attackPattern of results){
                     addAttackPatternToTable(attackPattern)
            }}
            else if (document.referrer == "http://127.0.0.1:5000/adversaries") {
                adURL = 'http://127.0.0.1:5000/api/adversary/' + document.title.split(": ")[1]
                $.ajax({
                    url: adURL,
                    method:'GET',
                    datatype:'JSON',
                    success:function(secondResults){
                for (attackPattern of results){
                    if (secondResults.includes(attackPattern.attackID)) {
                        addAttackPatternToTable(attackPattern)
               }}}})
            }
            else if (document.referrer == "http://127.0.0.1:5000/malware-tools") {
                adURL = 'http://127.0.0.1:5000/api/malware/' + document.title.split(": ")[1]
                $.ajax({
                    url: adURL,
                    data:"Malware",
                    method:'GET',
                    datatype:'JSON',
                    success:function(secondResults){
                for (attackPattern of results){
                    if (secondResults.includes(attackPattern.attackID)) {
                        addAttackPatternToTable(attackPattern)
               }}}})
            }
            else {
            for (attackPattern of results){
                if (attackPattern.tacticName.toLowerCase() == document.title.split(": ")[1].replaceAll(" ", "-").toLowerCase()) {
                     addAttackPatternToTable(attackPattern)
            }}}
       },
       error:function (xhr,status,error){
           console.log ("error "+error +" code:"+status)
       }

   })
   
}
function addAttackPatternToTable(attackPattern){
    //console.log("working so far")
    tableElem = document.getElementById("attackPatternTable")
    rowElem = tableElem.insertRow(-1)
    rowElem.setAttribute("id", attackPattern.attackID)
    cell1 = rowElem.insertCell(0)
    cell1.innerHTML = attackPattern.attackID
    cell2 = rowElem.insertCell(1)
    cell2.innerHTML = attackPattern.patternName
    cell3 = rowElem.insertCell(2)
    cell3.innerHTML = attackPattern.tacticName
    cell4 = rowElem.insertCell(3)
    cell4.innerHTML = attackPattern.description
    cell5 = rowElem.insertCell(4)
    cell5.innerHTML = attackPattern.assessment
    cell6 = rowElem.insertCell(5)
    cell6.innerHTML = '<button class="btn btn-success" onclick="showUpdate(this)">Update</button>'
    cell7 = rowElem.insertCell(6)
    cell7.innerHTML = '<button class="btn btn-danger" onclick="doDelete(this)">Delete</button>'
     }
populateTable()