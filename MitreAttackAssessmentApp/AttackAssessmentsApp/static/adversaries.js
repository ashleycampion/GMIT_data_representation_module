function showCreate(){
    document.getElementById('display').style.display = "none"
    document.getElementById('update-button').style.display = "none"
    document.getElementById('create-button').style.display = "block"
    document.getElementById('create-update').style.display = "block"
    document.getElementById('create-title').style.display = "block"
    document.getElementById('update-title').style.display = "none"
    var form = document.getElementById('createUpdateForm')
    form.querySelector('input[name="residualRisk"]').disabled=true
    form.querySelector('input[name="defense"]').disabled=true

}
function showUpdate(thisElem){
    var rowElement = thisElem.parentNode.parentNode;
    adversary = readAdversaryFromRow(rowElement)
    populateForm(adversary)

    document.getElementById('display').style.display = "none"
    document.getElementById('update-button').style.display = "block"
    document.getElementById('create-button').style.display = "none"
    document.getElementById('create-update').style.display = "block"
    document.getElementById('create-title').style.display = "none"
    document.getElementById('update-title').style.display = "block"

}
function readAdversaryFromRow(rowElement){
    adversary = {}
    adversary.name = rowElement.getAttribute("id");
    adversary.description = rowElement.cells[1].firstChild.textContent
    adversary.inherentRisk = rowElement.cells[2].firstChild.textContent
    adversary.defense = rowElement.cells[3].firstChild.textContent
    adversary.residualRisk = rowElement.cells[4].firstChild.textContent

    return adversary
    
}
function populateForm(adversary){
    var form = document.getElementById('createUpdateForm')

    
    form.querySelector('input[name="name"]').value = adversary.name
    form.querySelector('input[name="name"]').disabled=true
    
    form.querySelector('textarea[name="description"]').value = adversary.description
    form.querySelector('input[name="inherentRisk"]').value = adversary.inherentRisk
    form.querySelector('input[name="defense"]').value = adversary.defense
    form.querySelector('input[name="defense"]').disabled=true
    form.querySelector('input[name="residualRisk"]').value = adversary.residualRisk      
    form.querySelector('input[name="residualRisk"]').disabled=true
}
function clearForm() {
        var form = document.getElementById('createUpdateForm')


        form.querySelector('input[name="name"]').value = ''
        form.querySelector('input[name="name"]').disabled = false

        form.querySelector('textarea[name="description"]').value = ''
        form.querySelector('input[name="inherentRisk"]').value = ''
        form.querySelector('input[name="defense"]').value = ''
        form.querySelector('input[name="defense"]').disabled = true
        form.querySelector('input[name="residualRisk"]').value = ''
        form.querySelector('input[name="residualRisk"]').disabled = true
    }

function doCreate(){
    console.log("in doCreate")
    adversary= getAdversaryFromForm()
    console.log(adversary)
    $.ajax({
        url:"/api/adversaries",
        data:JSON.stringify(adversary),
        method:"POST",
        dataType:"JSON",
        contentType: "application/json; charset=utf-8",
        success:function(result){
            console.log(result) 
            addAdversaryToTable(adversary)
            showDisplay()
            clearForm()

        },
        error:function(xhr,status,error){
            console.log("error"+error)
        }
    })
   
}
function doUpdate(){
    adversary = getAdversaryFromForm()
    updateServer(adversary)
    
}
function updateServer(adversary){
   $.ajax({
        url: "/api/adversary/"+adversary.name,
        data: JSON.stringify(adversary),
        method: "PUT",
        dataType: "JSON",
        contentType: "application/json; charset=utf-8",
        success: function (result) {
            console.log(result)
            adversary.residualRisk = adversary.inherentRisk * adversary.defense / 100
            updateTableRow(adversary)
            showDisplay()
            clearForm()

        },
        error: function (xhr, status, error) {
            console.log("error" + error)
        }
    })
}
function doDelete(thisElem){
    var tableElement = document.getElementById('adversaryTable');
    var rowElement = thisElem.parentNode.parentNode;
    var index = rowElement.rowIndex;
    name = rowElement.getAttribute("id");
    $.ajax({
        url:"/api/"+name,
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
function updateTableRow(adversary){
    rowElement = document.getElementById(adversary.name)
    rowElement.cells[1].firstChild.textContent = adversary.description
    rowElement.cells[2].firstChild.textContent = adversary.inherentRisk
    rowElement.cells[3].firstChild.textContent = adversary.defense
    rowElement.cells[4].firstChild.textContent = adversary.residualRisk
    //console.log("updating table")
}
function getAdversaryFromForm(){
    var form = document.getElementById('createUpdateForm')

    var adversary = {}
    adversary.name = form.querySelector('input[name="name"]').value
    adversary.description = form.querySelector('textarea[name="description"]').value
    adversary.inherentRisk = form.querySelector('input[name="inherentRisk"]').value
    adversary.defense = form.querySelector('input[name="defense"]').value
    adversary.residualRisk = form.querySelector('input[name="residualRisk"]').value
    //console.log(adversary)
     return adversary
}
 function showDisplay() {
        document.getElementById('display').style.display = "block"
        document.getElementById('create-update').style.display = "none"

    }

function populateTable(){
    //ajax getAll
   $.ajax({
       url:'http://127.0.0.1:5000/api/adversaries',
       method:'GET',
       datatype:'JSON',
       success:function(results){
            for (adversary of results){
                 addAdversaryToTable(adversary)
            }
       },
       error:function (xhr,status,error){
           console.log ("error "+error +" code:"+status)
       }

   })
   
}
function addAdversaryToTable(adversary){
    //console.log("working so far")
    tableElem = document.getElementById("adversaryTable")
    rowElem = tableElem.insertRow(-1)
    rowElem.setAttribute("id", adversary.name)
    cell1 = rowElem.insertCell(0)
    cell1.innerHTML = adversary.name
    cell2 = rowElem.insertCell(1)
    cell2.innerHTML = adversary.description
    cell3 = rowElem.insertCell(2)
    cell3.innerHTML = adversary.inherentRisk
    cell4 = rowElem.insertCell(3)
    cell4.innerHTML = adversary.defense
    cell5 = rowElem.insertCell(4)
    cell5.innerHTML = adversary.residualRisk
    cell6 = rowElem.insertCell(5)
    cell6.innerHTML = '<button class="btn btn-info" onclick="viewTechniques(this)">Techniques</button>'
    cell7 = rowElem.insertCell(6)
    cell7.innerHTML = '<button class="btn btn-success" onclick="showUpdate(this)">Update</button>'
    cell8 = rowElem.insertCell(7)
    cell8.innerHTML = '<button class="btn btn-danger" onclick="doDelete(this)">Delete</button>'
     }


function viewTechniques(name) {
    name = name.parentNode.parentNode.getAttribute("id")
    url = 'techniques/' + name
    window.location.href= url
}



populateTable()