function showCreate(){
    document.getElementById('display').style.display = "none"
    document.getElementById('update-button').style.display = "none"
    document.getElementById('create-button').style.display = "block"
    document.getElementById('create-update').style.display = "block"
    document.getElementById('create-title').style.display = "block"
    document.getElementById('update-title').style.display = "none"
    var form = document.getElementById('createUpdateForm')
    form.querySelector('input[name="assessment"]').disabled=true

}
function showUpdate(thisElem){
    var rowElement = thisElem.parentNode.parentNode;
    tactic = readTacticFromRow(rowElement)
    console.log(tactic.log)
    populateForm(tactic)

    document.getElementById('display').style.display = "none"
    document.getElementById('update-button').style.display = "block"
    document.getElementById('create-button').style.display = "none"
    document.getElementById('create-update').style.display = "block"
    document.getElementById('create-title').style.display = "none"
    document.getElementById('update-title').style.display = "block"

}
function readTacticFromRow(rowElement){
    tactic = {}
    tactic.attackID = rowElement.getAttribute("id");
    tactic.tacticName = rowElement.cells[1].firstChild.textContent
    tactic.description = rowElement.cells[2].firstChild.textContent
    tactic.assessment = rowElement.cells[3].firstChild.textContent

    return tactic
    
}
function populateForm(tactic){
    var form = document.getElementById('createUpdateForm')

    
    form.querySelector('input[name="attackID"]').value = tactic.attackID
    form.querySelector('input[name="attackID"]').disabled=true
    
    form.querySelector('input[name="tacticName"]').value = tactic.tacticName
    form.querySelector('textarea[name="description"]').value = tactic.description
    form.querySelector('input[name="assessment"]').value = tactic.assessment
    form.querySelector('input[name="assessment"]').disabled=true      
}
function clearForm() {
        var form = document.getElementById('createUpdateForm')


        form.querySelector('input[name="attackID"]').value = ''
        form.querySelector('input[name="attackID"]').disabled = false

        form.querySelector('input[name="tacticName"]').value = ''
        form.querySelector('textarea[name="description"]').value = ''
        form.querySelector('input[name="assessment"]').value = ''
        form.querySelector('input[name="assessment"]').disabled = true
    }

function doCreate(){
    console.log("in doCreate")
    tactic= getTacticFromForm()
    console.log(tactic)
    $.ajax({
        url:"/api/tactics",
        data:JSON.stringify(tactic),
        method:"POST",
        dataType:"JSON",
        contentType: "application/json; charset=utf-8",
        success:function(result){
            console.log(result) 
            addTacticToTable(tactic)
            showDisplay()
            clearForm()

        },
        error:function(xhr,status,error){
            console.log("error"+error)
        }
    })
   
}
function doUpdate(){
    tactic = getTacticFromForm()
    updateServer(tactic)
    
}
function updateServer(tactic){
   $.ajax({
        url: "/api/"+tactic.attackID,
        data: JSON.stringify(tactic),
        method: "PUT",
        dataType: "JSON",
        contentType: "application/json; charset=utf-8",
        success: function (result) {
            console.log(result)
            updateTableRow(tactic)
            showDisplay()
            clearForm()

        },
        error: function (xhr, status, error) {
            console.log("error" + error)
        }
    })
}
function doDelete(thisElem){
    var tableElement = document.getElementById('tacticsTable');
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
function updateTableRow(tactic){
    rowElement = document.getElementById(tactic.attackID)
    rowElement.cells[1].firstChild.textContent = tactic.tacticName
    rowElement.cells[2].firstChild.textContent = tactic.description
    rowElement.cells[3].firstChild.textContent = tactic.assessment
    //console.log("updating table")
}
function getTacticFromForm(){
    var form = document.getElementById('createUpdateForm')

    var tactic = {}
    tactic.attackID = form.querySelector('input[name="attackID"]').value
    tactic.tacticName = form.querySelector('input[name="tacticName"]').value
    tactic.description = form.querySelector('textarea[name="description"]').value
    tactic.assessment = form.querySelector('input[name="assessment"]').value
    //console.log(tactic)
     return tactic
}
 function showDisplay() {
        document.getElementById('display').style.display = "block"
        document.getElementById('create-update').style.display = "none"

    }

function populateTable(){
    //ajax getAll
   $.ajax({
       url:'http://127.0.0.1:5000/api/tactics',
       method:'GET',
       datatype:'JSON',
       success:function(results){
            for (tactic of results){
                 addTacticToTable(tactic)
            }
       },
       error:function (xhr,status,error){
           console.log ("error "+error +" code:"+status)
       }

   })
   
}
function addTacticToTable(tactic){
    //console.log("working so far")
    tableElem = document.getElementById("tacticsTable")
    rowElem = tableElem.insertRow(-1)
    rowElem.setAttribute("id", tactic.attackID)
    cell1 = rowElem.insertCell(0)
    cell1.innerHTML = tactic.attackID
    cell2 = rowElem.insertCell(1)
    cell2.innerHTML = tactic.tacticName
    cell3 = rowElem.insertCell(2)
    cell3.innerHTML = tactic.description
    cell4 = rowElem.insertCell(3)
    cell4.innerHTML = tactic.assessment
    cell5 = rowElem.insertCell(4)
    cell5.innerHTML = '<button class="btn btn-success" onclick="showUpdate(this)">Update</button>'
    cell6 = rowElem.insertCell(5)
    cell6.innerHTML = '<button class="btn btn-danger" onclick="doDelete(this)">Delete</button>'
     }
populateTable()